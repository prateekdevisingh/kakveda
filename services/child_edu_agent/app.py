"""
Child Education Agent - Safe Q&A for 3+ Year Children
======================================================
Author: Prateek Chaudhary

Features:
- Educational Q&A for young children (3+ years)
- Adult/inappropriate content detection
- Parent alert system
- Integration with Kakveda failure intelligence
"""

import os
import re
import json
import logging
import asyncio
from datetime import datetime
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from enum import Enum

import httpx
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("child_edu_agent")

app = FastAPI(
    title="Child Education Agent",
    description="Safe educational Q&A for 3+ year children with parental alerts",
    version="0.1.0"
)

# Get template directory
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

# ============================================================================
# Configuration
# ============================================================================

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
EVENT_BUS_URL = os.getenv("EVENT_BUS_URL", "http://event-bus:8001")
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://dashboard:8110")
PARENT_ALERT_WEBHOOK = os.getenv("PARENT_ALERT_WEBHOOK", "")  # Optional webhook
PARENT_EMAIL = os.getenv("PARENT_EMAIL", "")  # Optional email

# Age-appropriate topics for 3+ years
ALLOWED_TOPICS = [
    "colors", "shapes", "animals", "fruits", "vegetables", "numbers",
    "alphabets", "rhymes", "stories", "body parts", "family", "friends",
    "weather", "seasons", "days", "months", "greetings", "manners",
    "vehicles", "nature", "birds", "flowers", "food", "toys", "games",
    "music", "dance", "art", "craft", "science basics", "space basics"
]

# Blocked keywords (adult/inappropriate content)
BLOCKED_KEYWORDS = [
    "violence", "kill", "death", "murder", "blood", "fight", "war",
    "alcohol", "beer", "wine", "drugs", "smoking", "cigarette",
    "gun", "weapon", "knife", "bomb", "terrorist",
    "sex", "nude", "naked", "porn", "adult",
    "abuse", "bully", "hate", "racist", "discrimination",
    "gambling", "casino", "betting",
    "horror", "ghost", "scary", "nightmare", "demon",
    "swear", "curse", "bad words", "slang"
]

# ============================================================================
# Data Models
# ============================================================================

class ContentRating(str, Enum):
    SAFE = "safe"
    WARNING = "warning"
    BLOCKED = "blocked"

@dataclass
class ContentAnalysis:
    rating: ContentRating
    is_educational: bool
    detected_topics: List[str]
    blocked_keywords: List[str]
    confidence: float
    explanation: str

class QuestionRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=500)
    child_name: Optional[str] = "Little One"
    child_age: Optional[int] = Field(default=3, ge=3, le=10)
    session_id: Optional[str] = None

class AnswerResponse(BaseModel):
    question: str
    answer: str
    is_safe: bool
    content_rating: str
    detected_topics: List[str]
    timestamp: str
    session_id: str
    alert_sent: bool = False

class ParentAlert(BaseModel):
    alert_type: str  # "blocked_content", "warning", "unusual_pattern"
    question: str
    detected_keywords: List[str]
    child_name: str
    timestamp: str
    severity: str  # "low", "medium", "high"
    recommendation: str

# ============================================================================
# Content Safety Analyzer
# ============================================================================

class ContentSafetyAnalyzer:
    """Analyzes content for child safety"""
    
    def __init__(self):
        self.blocked_pattern = re.compile(
            r'\b(' + '|'.join(map(re.escape, BLOCKED_KEYWORDS)) + r')\b',
            re.IGNORECASE
        )
        self.topic_patterns = {
            topic: re.compile(rf'\b{re.escape(topic)}\b', re.IGNORECASE)
            for topic in ALLOWED_TOPICS
        }
    
    def analyze(self, text: str) -> ContentAnalysis:
        """Analyze text for safety and educational value"""
        text_lower = text.lower()
        
        # Check for blocked keywords
        blocked_found = self.blocked_pattern.findall(text_lower)
        blocked_keywords = list(set([kw.lower() for kw in blocked_found]))
        
        # Detect educational topics
        detected_topics = []
        for topic, pattern in self.topic_patterns.items():
            if pattern.search(text_lower):
                detected_topics.append(topic)
        
        # Determine rating
        if blocked_keywords:
            rating = ContentRating.BLOCKED
            is_educational = False
            confidence = 0.95
            explanation = f"Blocked content detected: {', '.join(blocked_keywords)}"
        elif detected_topics:
            rating = ContentRating.SAFE
            is_educational = True
            confidence = 0.85
            explanation = f"Educational topics detected: {', '.join(detected_topics)}"
        else:
            # Unknown topic - needs review
            rating = ContentRating.WARNING
            is_educational = False
            confidence = 0.6
            explanation = "Topic not recognized as child-appropriate. Proceeding with caution."
        
        return ContentAnalysis(
            rating=rating,
            is_educational=is_educational,
            detected_topics=detected_topics,
            blocked_keywords=blocked_keywords,
            confidence=confidence,
            explanation=explanation
        )

# Initialize analyzer
safety_analyzer = ContentSafetyAnalyzer()

# ============================================================================
# Educational Response Generator
# ============================================================================

CHILD_FRIENDLY_SYSTEM_PROMPT = """You are a friendly, kind, and patient teacher for young children aged 3-10 years.

RULES:
1. Use simple words that a 3-year-old can understand
2. Be warm, encouraging, and use positive language
3. Add fun elements like emojis where appropriate
4. Keep answers short (2-4 sentences)
5. Never discuss violence, adult themes, or scary topics
6. If asked something inappropriate, gently redirect to a fun topic
7. Use examples from nature, animals, or everyday life
8. Be enthusiastic and make learning fun!

Examples of good responses:
- "Great question! 🌈 The sky is blue because..."
- "Wow, you're so curious! 🐱 Cats say meow because..."
- "That's a wonderful thing to ask! 🌻 Flowers grow from tiny seeds..."
"""

async def generate_educational_response(
    question: str,
    child_name: str,
    child_age: int,
    analysis: ContentAnalysis
) -> str:
    """Generate age-appropriate educational response"""
    
    # If content is blocked, return safe redirect
    if analysis.rating == ContentRating.BLOCKED:
        return f"Hey {child_name}! 🌈 Let's talk about something fun instead! Do you want to learn about animals, colors, or maybe hear a fun story? What sounds exciting to you? 🎉"
    
    # Try Ollama first
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": "llama3.2",
                    "prompt": f"{CHILD_FRIENDLY_SYSTEM_PROMPT}\n\nChild's name: {child_name}\nChild's age: {child_age} years\nQuestion: {question}\n\nProvide a simple, fun, educational answer:",
                    "stream": False,
                    "options": {
                        "temperature": 0.7,
                        "num_predict": 150
                    }
                }
            )
            if response.status_code == 200:
                data = response.json()
                return data.get("response", "").strip()
    except Exception as e:
        logger.warning(f"Ollama not available: {e}")
    
    # Fallback: Simple predefined responses
    return get_fallback_response(question, child_name, analysis.detected_topics)


def get_fallback_response(question: str, child_name: str, topics: List[str]) -> str:
    """Fallback responses when LLM is not available"""
    
    question_lower = question.lower()
    
    # Color questions
    if any(word in question_lower for word in ["color", "colour", "red", "blue", "green", "yellow"]):
        return f"Great question, {child_name}! 🌈 Colors are everywhere! Red is like apples and strawberries. Blue is like the sky and ocean. Yellow is like the sun and bananas! What's your favorite color?"
    
    # Animal questions
    if any(word in question_lower for word in ["animal", "dog", "cat", "bird", "fish", "elephant"]):
        return f"Wow, you love animals, {child_name}! 🐾 Animals are amazing friends. Dogs say 'woof woof', cats say 'meow', and birds sing beautiful songs! Do you have a favorite animal?"
    
    # Number questions
    if any(word in question_lower for word in ["number", "count", "how many", "1", "2", "3"]):
        return f"Let's count together, {child_name}! 🔢 One, two, three, four, five! Can you count your fingers? You have five on each hand, that makes ten! Great job counting!"
    
    # Alphabet questions
    if any(word in question_lower for word in ["alphabet", "letter", "abc", "a b c"]):
        return f"A-B-C is so much fun, {child_name}! 📚 A is for Apple, B is for Ball, C is for Cat! Can you sing the ABC song with me? It's a great way to learn!"
    
    # Family questions
    if any(word in question_lower for word in ["family", "mama", "papa", "mom", "dad", "sister", "brother"]):
        return f"Family is wonderful, {child_name}! 👨‍👩‍👧 Families love and take care of each other. Mommy, daddy, brothers, sisters - they all make home special! Who is in your family?"
    
    # Weather questions
    if any(word in question_lower for word in ["weather", "rain", "sun", "cloud", "snow"]):
        return f"Weather is exciting, {child_name}! ☀️🌧️ Sometimes the sun shines bright, sometimes clouds bring rain for the flowers, and sometimes snow falls like white fluffy blankets! What weather do you like?"
    
    # Default educational response
    return f"That's a wonderful question, {child_name}! 🌟 I love how curious you are. Learning new things is like going on an adventure! Would you like to learn about animals, colors, or maybe sing a rhyme together?"

# ============================================================================
# Parent Alert System
# ============================================================================

async def send_parent_alert(alert: ParentAlert):
    """Send alert to parents about concerning content"""
    
    logger.warning(f"PARENT ALERT: {alert.alert_type} - {alert.question}")
    
    # Store alert in event bus (Kakveda integration)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{EVENT_BUS_URL}/publish",
                json={
                    "topic": "child_safety_alert",
                    "payload": asdict(alert) if hasattr(alert, '__dataclass_fields__') else alert.dict()
                }
            )
    except Exception as e:
        logger.error(f"Failed to publish to event bus: {e}")
    
    # Send webhook if configured
    if PARENT_ALERT_WEBHOOK:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    PARENT_ALERT_WEBHOOK,
                    json=alert.dict()
                )
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
    
    # Log for dashboard
    logger.info(f"Alert logged for dashboard: {json.dumps(alert.dict(), indent=2)}")

# ============================================================================
# Kakveda Integration
# ============================================================================

async def report_to_kakveda(
    question: str,
    answer: str,
    analysis: ContentAnalysis,
    session_id: str
):
    """Report interaction to Kakveda for failure intelligence"""
    
    trace_data = {
        "trace_id": session_id,
        "service": "child_edu_agent",
        "operation": "question_answer",
        "input": question,
        "output": answer,
        "metadata": {
            "content_rating": analysis.rating.value,
            "is_educational": analysis.is_educational,
            "detected_topics": analysis.detected_topics,
            "blocked_keywords": analysis.blocked_keywords,
            "confidence": analysis.confidence
        },
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # If blocked content, report as failure
    if analysis.rating == ContentRating.BLOCKED:
        trace_data["status"] = "failure"
        trace_data["error"] = "Blocked content detected"
    else:
        trace_data["status"] = "success"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{EVENT_BUS_URL}/publish",
                json={
                    "topic": "trace.ingested",
                    "payload": trace_data
                }
            )
    except Exception as e:
        logger.warning(f"Failed to report to Kakveda: {e}")

# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the Kids UI"""
    try:
        template_path = os.path.join(TEMPLATE_DIR, "index.html")
        if os.path.exists(template_path):
            with open(template_path, "r") as f:
                return HTMLResponse(content=f.read())
    except Exception as e:
        logger.error(f"Failed to load template: {e}")
    
    # Fallback JSON response
    return HTMLResponse(content="""
    <html>
    <head><title>Kakveda Kids</title></head>
    <body style="font-family: Comic Sans MS; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea, #764ba2);">
        <h1 style="color: white;">🎒 Kakveda Kids</h1>
        <p style="color: white;">Child Education Agent is running!</p>
        <p style="color: white;">Use POST /api/ask to ask questions.</p>
    </body>
    </html>
    """)

@app.get("/api")
async def api_info():
    """API info endpoint"""
    return {
        "service": "Child Education Agent",
        "version": "0.1.0",
        "status": "running",
        "description": "Safe educational Q&A for 3+ year children",
        "endpoints": {
            "ui": "/",
            "ask": "/api/ask",
            "topics": "/api/topics",
            "health": "/health"
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.post("/api/ask", response_model=AnswerResponse)
async def ask_question(
    request: QuestionRequest,
    background_tasks: BackgroundTasks
):
    """
    Ask an educational question for young children.
    Automatically detects and blocks inappropriate content.
    """
    
    session_id = request.session_id or f"session_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    timestamp = datetime.utcnow().isoformat()
    
    # Analyze content safety
    analysis = safety_analyzer.analyze(request.question)
    
    alert_sent = False
    
    # Handle blocked content
    if analysis.rating == ContentRating.BLOCKED:
        # Send parent alert
        alert = ParentAlert(
            alert_type="blocked_content",
            question=request.question,
            detected_keywords=analysis.blocked_keywords,
            child_name=request.child_name,
            timestamp=timestamp,
            severity="high",
            recommendation="Please review the chat history and talk to your child about appropriate topics."
        )
        background_tasks.add_task(send_parent_alert, alert)
        alert_sent = True
        
        logger.warning(f"BLOCKED: {request.question} | Keywords: {analysis.blocked_keywords}")
    
    # Handle warning content
    elif analysis.rating == ContentRating.WARNING:
        alert = ParentAlert(
            alert_type="warning",
            question=request.question,
            detected_keywords=[],
            child_name=request.child_name,
            timestamp=timestamp,
            severity="medium",
            recommendation="Question topic was not recognized. Please review."
        )
        background_tasks.add_task(send_parent_alert, alert)
        alert_sent = True
    
    # Generate response
    answer = await generate_educational_response(
        request.question,
        request.child_name,
        request.child_age,
        analysis
    )
    
    # Report to Kakveda
    background_tasks.add_task(
        report_to_kakveda,
        request.question,
        answer,
        analysis,
        session_id
    )
    
    return AnswerResponse(
        question=request.question,
        answer=answer,
        is_safe=analysis.rating == ContentRating.SAFE,
        content_rating=analysis.rating.value,
        detected_topics=analysis.detected_topics,
        timestamp=timestamp,
        session_id=session_id,
        alert_sent=alert_sent
    )

# Keep old endpoint for backward compatibility
@app.post("/ask", response_model=AnswerResponse)
async def ask_question_legacy(
    request: QuestionRequest,
    background_tasks: BackgroundTasks
):
    """Legacy endpoint - redirects to /api/ask"""
    return await ask_question(request, background_tasks)

@app.get("/api/topics")
async def get_allowed_topics():
    """Get list of allowed educational topics"""
    return {
        "allowed_topics": ALLOWED_TOPICS,
        "description": "These are age-appropriate topics for 3+ year children"
    }

@app.get("/topics")
async def get_topics_legacy():
    """Legacy endpoint"""
    return await get_allowed_topics()

@app.post("/api/analyze")
async def analyze_content(text: str):
    """Analyze text for content safety (for testing)"""
    analysis = safety_analyzer.analyze(text)
    return asdict(analysis)

@app.post("/analyze")
async def analyze_content_legacy(text: str):
    """Legacy endpoint"""
    return await analyze_content(text)

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8120)

# Child Education Agent 🎒

Safe educational Q&A agent for young children (3+ years) with parental alerts.

## Features

✅ **Educational Q&A** - Age-appropriate answers for curious kids  
✅ **Content Safety** - Blocks inappropriate/adult content  
✅ **Parent Alerts** - Notifies parents of concerning queries  
✅ **Kakveda Integration** - Failure intelligence tracking  
✅ **LLM Powered** - Uses Ollama for natural responses  
✅ **Fallback Mode** - Works without LLM using predefined responses  

## Allowed Topics

- Colors, Shapes, Numbers, Alphabets
- Animals, Birds, Nature, Flowers
- Family, Friends, Manners, Greetings
- Weather, Seasons, Days, Months
- Rhymes, Stories, Music, Dance
- Vehicles, Food, Toys, Games
- Basic Science, Space basics

## Blocked Content

The agent automatically blocks and alerts parents about:
- Violence, weapons, war
- Adult/inappropriate content
- Alcohol, drugs, smoking
- Horror, scary content
- Hate speech, bullying

## API Endpoints

### Ask Question
```bash
POST /ask
{
    "question": "Why is the sky blue?",
    "child_name": "Arya",
    "child_age": 4
}
```

### Response
```json
{
    "question": "Why is the sky blue?",
    "answer": "Great question, Arya! 🌈 The sky looks blue because...",
    "is_safe": true,
    "content_rating": "safe",
    "detected_topics": ["colors", "nature"],
    "alert_sent": false
}
```

### Get Allowed Topics
```bash
GET /topics
```

### Analyze Content (Testing)
```bash
POST /analyze?text=your text here
```

## Running Standalone

```bash
cd services/child_edu_agent
pip install -r requirements.txt
python app.py
```

Access: http://localhost:8120

## Running with Docker Compose

The agent integrates with the main Kakveda stack. See main README.

## Parent Alert System

When inappropriate content is detected:

1. Question is blocked
2. Child receives a safe redirect response
3. Parent alert is generated with:
   - Detected keywords
   - Severity level
   - Recommendations
4. Alert is sent to:
   - Kakveda event bus (for tracking)
   - Webhook (if configured)
   - Dashboard logs

## Environment Variables

```bash
OLLAMA_URL=http://ollama:11434
EVENT_BUS_URL=http://event-bus:8001
PARENT_ALERT_WEBHOOK=https://your-webhook.com
PARENT_EMAIL=parent@example.com
```

## Kakveda Integration

This agent reports all interactions to Kakveda's failure intelligence system:
- Safe questions → tracked as success
- Blocked content → tracked as failure
- Patterns detected over time
- Health scoring for child safety

---

**Author:** Prateek Chaudhary  
**License:** Apache 2.0

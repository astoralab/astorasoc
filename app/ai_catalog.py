AI_PROVIDERS = {
    "openai": {
        "label": "OpenAI (Official API / Paid)",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("gpt-5.5", "GPT-5.5 / Paid API"),
            ("gpt-5.5-mini", "GPT-5.5 Mini / Paid API"),
            ("gpt-5.5-nano", "GPT-5.5 Nano / Low-cost API"),
        ],
    },
    "gemini": {
        "label": "Google Gemini",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("gemini-2.5-pro", "Gemini 2.5 Pro"),
            ("gemini-2.5-flash", "Gemini 2.5 Flash / Free tier"),
            ("gemini-2.0-flash", "Gemini 2.0 Flash / Free tier"),
            ("gemini-1.5-flash", "Gemini 1.5 Flash / Free tier"),
        ],
    },
    "anthropic": {
        "label": "Anthropic Claude (Official API / Paid)",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("claude-sonnet", "Claude Sonnet / Paid API"),
            ("claude-opus", "Claude Opus / Paid API"),
            ("claude-haiku", "Claude Haiku / Low-cost"),
        ],
    },
    "deepseek": {
        "label": "DeepSeek (Official API / Low-cost)",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("deepseek-chat", "DeepSeek Chat / Low-cost API"),
            ("deepseek-reasoner", "DeepSeek Reasoner / Low-cost API"),
        ],
    },
    "deepseek_openrouter_free": {
        "label": "DeepSeek Free (via OpenRouter)",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("deepseek/deepseek-r1:free", "DeepSeek R1 / Free"),
            ("deepseek/deepseek-chat-v3-0324:free", "DeepSeek Chat V3 / Free"),
            ("deepseek/deepseek-r1-distill-llama-70b:free", "DeepSeek R1 Distill Llama 70B / Free"),
            ("deepseek/deepseek-r1-distill-qwen-32b:free", "DeepSeek R1 Distill Qwen 32B / Free"),
        ],
    },
    "openrouter": {
        "label": "OpenRouter (Free Models)",
        "endpoint": "https://openrouter.ai/api/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("deepseek/deepseek-r1:free", "DeepSeek R1 / Free"),
            ("deepseek/deepseek-chat-v3-0324:free", "DeepSeek Chat V3 / Free"),
            ("google/gemma-3-27b-it:free", "Gemma 3 27B / Free"),
            ("meta-llama/llama-3.3-70b-instruct:free", "Llama 3.3 70B / Free"),
            ("mistralai/mistral-small-3.2-24b-instruct:free", "Mistral Small 3.2 / Free"),
            ("openai/gpt-5.5", "GPT-5.5"),
            ("openai/gpt-5.5-mini", "GPT-5.5 Mini"),
            ("google/gemini-2.5-pro", "Gemini 2.5 Pro"),
            ("anthropic/claude-sonnet", "Claude Sonnet"),
        ],
    },
    "azure_openai": {
        "label": "Azure OpenAI",
        "endpoint": "",
        "requires_key": True,
        "requires_endpoint": True,
        "models": [
            ("gpt-5.5", "GPT-5.5"),
            ("gpt-5.5-mini", "GPT-5.5 Mini"),
        ],
    },
    "groq": {
        "label": "Groq Cloud (Free Tier)",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("llama-3.3-70b-versatile", "Llama 3.3 70B Versatile / Free tier"),
            ("llama-3.1-8b-instant", "Llama 3.1 8B Instant / Free tier"),
            ("gemma2-9b-it", "Gemma 2 9B / Free tier"),
            ("mixtral-8x7b-32768", "Mixtral 8x7B / Free tier"),
        ],
    },
    "huggingface": {
        "label": "Hugging Face Router (Free/Community)",
        "endpoint": "https://router.huggingface.co/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("meta-llama/Llama-3.1-8B-Instruct", "Llama 3.1 8B Instruct / Community"),
            ("Qwen/Qwen2.5-72B-Instruct", "Qwen 2.5 72B Instruct / Community"),
            ("mistralai/Mistral-7B-Instruct-v0.3", "Mistral 7B Instruct / Community"),
            ("deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", "DeepSeek R1 Distill Qwen 32B / Community"),
        ],
    },
    "together": {
        "label": "Together AI (Free Credits)",
        "endpoint": "https://api.together.xyz/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("meta-llama/Llama-3.3-70B-Instruct-Turbo-Free", "Llama 3.3 70B Turbo / Free"),
            ("meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo", "Llama 3.1 8B Turbo"),
            ("Qwen/Qwen2.5-72B-Instruct-Turbo", "Qwen 2.5 72B Turbo"),
            ("mistralai/Mixtral-8x7B-Instruct-v0.1", "Mixtral 8x7B"),
        ],
    },
    "cerebras": {
        "label": "Cerebras (Free Tier)",
        "endpoint": "https://api.cerebras.ai/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("llama3.1-8b", "Llama 3.1 8B / Free tier"),
            ("llama-3.3-70b", "Llama 3.3 70B / Free tier"),
        ],
    },
    "fireworks": {
        "label": "Fireworks AI (Free Credits)",
        "endpoint": "https://api.fireworks.ai/inference/v1/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("accounts/fireworks/models/llama-v3p1-8b-instruct", "Llama 3.1 8B Instruct"),
            ("accounts/fireworks/models/llama-v3p3-70b-instruct", "Llama 3.3 70B Instruct"),
            ("accounts/fireworks/models/qwen2p5-72b-instruct", "Qwen 2.5 72B Instruct"),
        ],
    },
    "deepinfra": {
        "label": "DeepInfra (Free Credits)",
        "endpoint": "https://api.deepinfra.com/v1/openai/chat/completions",
        "requires_key": True,
        "requires_endpoint": False,
        "models": [
            ("meta-llama/Meta-Llama-3.1-8B-Instruct", "Llama 3.1 8B Instruct"),
            ("meta-llama/Llama-3.3-70B-Instruct", "Llama 3.3 70B Instruct"),
            ("Qwen/Qwen2.5-72B-Instruct", "Qwen 2.5 72B Instruct"),
            ("mistralai/Mistral-7B-Instruct-v0.3", "Mistral 7B Instruct"),
        ],
    },
    "ollama": {
        "label": "Ollama (Local Free)",
        "endpoint": "http://localhost:11434",
        "requires_key": False,
        "requires_endpoint": True,
        "models": [
            ("llama3.1:8b", "Llama 3.1 8B / Local free"),
            ("llama3.3:70b", "Llama 3.3 70B / Local free"),
            ("qwen2.5:7b", "Qwen 2.5 7B / Local free"),
            ("qwen2.5:72b", "Qwen 2.5 72B / Local free"),
            ("mistral-nemo", "Mistral Nemo / Local free"),
            ("deepseek-r1:8b", "DeepSeek R1 8B / Local free"),
            ("gemma3:12b", "Gemma 3 12B / Local free"),
        ],
    },
    "custom": {
        "label": "Custom OpenAI-Compatible",
        "endpoint": "",
        "requires_key": True,
        "requires_endpoint": True,
        "models": [
            ("gpt-5.5", "GPT-5.5"),
            ("gpt-5.5-mini", "GPT-5.5 Mini"),
            ("llama-3.1", "Llama 3.1"),
            ("qwen2.5", "Qwen 2.5"),
            ("deepseek-r1", "DeepSeek R1"),
        ],
    },
}


def provider_choices():
    return [(key, value["label"]) for key, value in AI_PROVIDERS.items()]


def all_model_choices():
    seen = set()
    choices = []
    for provider in AI_PROVIDERS.values():
        for value, label in provider["models"]:
            if value in seen:
                continue
            seen.add(value)
            choices.append((value, label))
    return choices


def models_for_provider(provider):
    return AI_PROVIDERS.get(provider, AI_PROVIDERS["openai"])["models"]


def provider_label(provider):
    return AI_PROVIDERS.get(provider, {}).get("label", provider or "AI Provider")


def model_label(provider, model):
    for value, label in models_for_provider(provider):
        if value == model:
            return label
    return model or "AI Model"


def provider_requires_endpoint(provider):
    return bool(AI_PROVIDERS.get(provider, {}).get("requires_endpoint"))


def provider_requires_key(provider):
    return bool(AI_PROVIDERS.get(provider, AI_PROVIDERS["openai"]).get("requires_key", True))


def default_endpoint(provider):
    return AI_PROVIDERS.get(provider, AI_PROVIDERS["openai"]).get("endpoint", "")


def valid_model(provider, model):
    return model in {value for value, _ in models_for_provider(provider)}

# 2nd Eye — mobile

- `android/`: Android app (Kotlin, minSdk 26, arm64). Open the `android/` folder in Android Studio; it creates its own
  `local.properties` with your SDK path. The app watches WhatsApp through an accessibility service and shows a full-screen
  warning; optional on-device model `scamshield-3b.gguf` via llama.cpp (JNI).
- `engine/`: Python engine + FastAPI server + dashboard using the same rules and the fine-tuned `scamshield-3b` through Ollama.

Full description, the model and its training data, known gaps and security notes: [docs/MOBILE.md](../docs/MOBILE.md).

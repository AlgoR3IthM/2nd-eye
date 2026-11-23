#include <jni.h>
#include <string>
#include <vector>
#include "llama.h"

static llama_model* g_model = nullptr;
static llama_context* g_ctx = nullptr;

extern "C" JNIEXPORT jboolean JNICALL
Java_com_algor3ithm_scamshield_OnDeviceLlm_initModel(JNIEnv* env, jobject, jstring jpath) {
    if (g_model != nullptr) return JNI_TRUE;
    const char* path = env->GetStringUTFChars(jpath, nullptr);

    llama_backend_init();
    llama_model_params mparams = llama_model_default_params();
    g_model = llama_model_load_from_file(path, mparams);
    env->ReleaseStringUTFChars(jpath, path);
    if (!g_model) return JNI_FALSE;

    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx = 1024;
    cparams.n_threads = 4;
    cparams.n_threads_batch = 4;
    g_ctx = llama_init_from_model(g_model, cparams);
    return g_ctx != nullptr ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_algor3ithm_scamshield_OnDeviceLlm_generateJson(JNIEnv* env, jobject, jstring jprompt) {
    if (!g_model || !g_ctx) return env->NewStringUTF("{}");

    const char* prompt = env->GetStringUTFChars(jprompt, nullptr);
    const llama_vocab* vocab = llama_model_get_vocab(g_model);

    std::vector<llama_token> tokens(strlen(prompt) + 32);
    int n_tokens = llama_tokenize(vocab, prompt, strlen(prompt), tokens.data(), tokens.size(), true, true);
    if (n_tokens < 0) {
        tokens.resize(-n_tokens);
        n_tokens = llama_tokenize(vocab, prompt, strlen(prompt), tokens.data(), tokens.size(), true, true);
    }
    tokens.resize(n_tokens);

    llama_kv_self_clear(g_ctx);
    llama_batch batch = llama_batch_get_one(tokens.data(), tokens.size());
    if (llama_decode(g_ctx, batch) != 0) {
        env->ReleaseStringUTFChars(jprompt, prompt);
        return env->NewStringUTF("{}");
    }

    auto sparams = llama_sampler_chain_default_params();
    llama_sampler* smpl = llama_sampler_chain_init(sparams);
    llama_sampler_chain_add(smpl, llama_sampler_init_temp(0.0f));
    llama_sampler_chain_add(smpl, llama_sampler_init_dist(42));

    std::string output;
    for (int i = 0; i < 220; ++i) {
        llama_token id = llama_sampler_sample(smpl, g_ctx, -1);
        if (llama_vocab_is_eog(vocab, id)) break;

        char buf[128];
        int n = llama_token_to_piece(vocab, id, buf, sizeof(buf), 0, true);
        if (n > 0) output.append(buf, n);

        llama_batch next = llama_batch_get_one(&id, 1);
        if (llama_decode(g_ctx, next) != 0) break;
    }

    llama_sampler_free(smpl);
    env->ReleaseStringUTFChars(jprompt, prompt);
    return env->NewStringUTF(output.c_str());
}
# Foundation-Sec local investigation model

The default investigation model is `foundation-sec:8b`, a local Ollama
variant of Cisco Foundation AI's Foundation-Sec-1.1-8B-Instruct Q4_K_M.
The quantized model download is approximately 4.92 GB; runtime RAM and GPU
memory depend on context, offload, other applications, and Ollama settings.

Pull the model before enabling investigations:

```powershell
docker compose exec ollama ollama pull hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M
docker compose cp docker/ollama/FoundationSec.Modelfile ollama:/tmp/FoundationSec.Modelfile
docker compose exec ollama ollama create foundation-sec:8b -f /tmp/FoundationSec.Modelfile
docker compose exec ollama ollama list
docker compose exec ollama ollama ps
```

Use the same Compose override files used to start your system. Set `AGENT_MODEL`
and `OLLAMA_MODEL` to `foundation-sec:8b`, and set `OLLAMA_MODEL_ALIAS` to
`foundation_sec_1_1_8b`. Recreate the application container after changing its
environment. Keep `OLLAMA_NUM_CTX` and `OLLAMA_NUM_PREDICT` appropriately sized
for available memory. The source model advertises a larger context than the
runtime's configured context; they are not equivalent.

The original GGUF model does not expose native tool support in the installed
Ollama version. The local Modelfile supplies a Llama 3.1 tool template and the
client translates only strictly validated, known-tool JSON calls. Tool calling
and structured output must be tested with the installed Ollama
version and model template before relying on the investigation workflow. An
available model or successful text completion alone does not prove tool calling
works. Playbooks are selected from existing knowledge and do not execute actions.

Model card: https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct
Quantization: https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF

# RedSage-Qwen3-8B-DPO

Model dieu tra mac dinh la RedSage-Qwen3-8B-DPO Q4_K_M. Ban GGUF duoc luong tu hoa boi ben thu ba, khong phai ban do nhom tac gia phat hanh truc tiep.

```powershell
docker compose exec ollama ollama pull hf.co/mradermacher/RedSage-Qwen3-8B-DPO-GGUF:Q4_K_M
docker compose exec ollama ollama list
docker compose exec ollama ollama ps
```

Dat `OLLAMA_MODEL` va `AGENT_MODEL` bang ten day du nhu tren, `OLLAMA_MODEL_ALIAS=redsage_8b_dpo`; recreate container app de nap cau hinh. Kich thuoc tai khoang 5.03 GB; RAM va VRAM khi chay con phu thuoc context va cac dich vu khac. Kha nang tool calling va chat luong tieng Viet can duoc kiem chung tren moi truong thuc te. Khong xoa model cu de co the quay lai neu can.

- Model goc: https://huggingface.co/RISys-Lab/RedSage-Qwen3-8B-DPO
- GGUF: https://huggingface.co/mradermacher/RedSage-Qwen3-8B-DPO-GGUF

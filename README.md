# mAIware - AI Malware Detector 🛡️

Phân tích file PE (`.exe`, `.dll`) bằng AI, phân loại: **benign** (an toàn), **suspicious** (nghi ngờ), **malware** (độc hại).

## 🚀 Cài đặt

```bash
# 1. Clone repo
git clone https://github.com/vuquangtien/mAIware---AI.git
cd mAIware---AI

# 2. Tải models từ Releases
# Truy cập: https://github.com/vuquangtien/mAIware---AI/releases
# Tải file ensemble_models.zip và giải nén vào thư mục ensemble_models/

# 3. Cài thư viện
pip install -r requirements.txt
```

## 💻 Sử dụng

```bash
# Tạo thư mục chứa file .exe cần quét
mkdir samples
cp your_file.exe temp_scan/

# Chạy phân tích
python3 ensemble_predict_dir.py temp_scan/
```

**Kết quả:** File `samples_voting_result.csv` chứa kết quả phân loại.

```csv
sample_name,ensemble_class,ensemble_score
your_file.exe,malware,0.85
```

## 🗺️ Trích xuất call graph (tùy chọn)

```bash
python3 extract_callgraph.py your_file.exe -o callgraph --render
```

Kết quả: tạo `callgraph.callgraph.dot` (và `callgraph.callgraph.png` nếu có Graphviz).

---
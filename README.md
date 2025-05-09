# How to run
## install requirements
```
pip install -r requirements.txt
```
## run client
```
export PYTHONPATH="$PYTHONPATH:$PWD"
export PLATFORM_API_KEY=<YOUR_API_KEY>
PLATFORM=openai
MODEL=gpt-4
export TEE_TLS_URL=http://43.201.148.220:8000/
python3 main.py
```

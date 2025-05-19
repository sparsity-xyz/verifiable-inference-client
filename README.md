# How to run
## install requirements
```
pip install -r requirements.txt
```
## run client
```
export PYTHONPATH="$PYTHONPATH:$PWD"
export PLATFORM_API_KEY=<OPENAI_API_KEY>
export PLATFORM=openai
export MODEL=gpt-4
export TEE_TLS_URL=http://3.38.149.107:8000/
python3 main.py
```

For a step-by-step walkthrough, see [docs/tutorial.md](docs/tutorial.md).

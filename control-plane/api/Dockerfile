FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Build-time gateway assembly + integrity check
RUN python assemble_main.py && \
    test -f main_full.py && \
    python -c "import ast; ast.parse(open('main_full.py').read())"
EXPOSE 8080
# Runtime still goes through main.py bootstrap (re-verifies if needed)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

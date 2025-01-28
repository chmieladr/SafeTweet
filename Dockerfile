FROM python:3.12.8-slim

RUN apt-get update && apt-get upgrade -y && apt-get clean

WORKDIR /app
COPY . /app

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

ENV FLASK_APP=app.py

CMD ["python3", "gen_env.py"]
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
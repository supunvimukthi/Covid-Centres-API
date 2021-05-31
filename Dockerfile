FROM python:3.8.2
WORKDIR /code
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5100
CMD [ "gunicorn", "-w", "4", "--bind", "0.0.0.0:5100", "wsgi:app"]
FROM python:3.12-alpine3.21
# make sure to use a tag that won't be updated by the image maintainers

RUN mkdir /app
WORKDIR /app

RUN apk add postgresql-dev

COPY . /app/

COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt


EXPOSE 1337
CMD ["python3", "/app/startup.py"]

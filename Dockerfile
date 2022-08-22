FROM python:3

ENV URL_PREFIX=/bank/api/
ENV DATABASE_PATH=/database/bank.db
ENV PORT_NUMBER=9044

WORKDIR /usr/src/app

RUN pip install --upgrade pip

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

CMD waitress-serve --port=$PORT_NUMBER --call --url-prefix=$URL_PREFIX bank:create_app


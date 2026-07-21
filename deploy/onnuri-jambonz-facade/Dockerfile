FROM --platform=linux/amd64 python:3.13.14-slim@sha256:afe189875f1d2f9b45e287834fb9f2c273a5d59d354ae4050ab9affbf0a6ba06 AS dependencies

RUN python -m pip install --no-cache-dir --target /opt/python \
        cryptography==49.0.0 \
        fastapi==0.135.3 \
        httpx==0.28.1 \
        pydantic==2.13.4 \
        uvicorn==0.35.0

FROM --platform=linux/amd64 python:3.13.14-slim@sha256:afe189875f1d2f9b45e287834fb9f2c273a5d59d354ae4050ab9affbf0a6ba06
ARG FACADE_SOURCE_SHA256
RUN test "${#FACADE_SOURCE_SHA256}" -eq 64

LABEL org.opencontainers.image.source="https://github.com/slit-company/recova-voice" \
      org.opencontainers.image.licenses="LicenseRef-Recova-Proprietary" \
      org.recova.source-tree.sha256="$FACADE_SOURCE_SHA256" \
      org.recova.base.digest="python:3.13.14-slim@sha256:afe189875f1d2f9b45e287834fb9f2c273a5d59d354ae4050ab9affbf0a6ba06"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/srv/recova \
    PYTHONNOUSERSITE=1

WORKDIR /srv/recova
COPY --from=dependencies /opt/python/ /usr/local/lib/python3.13/site-packages/
COPY --chown=65532:65532 api/schemas/onnuri_smoke.py ./api/schemas/onnuri_smoke.py
COPY --chown=65532:65532 api/services/telephony/providers/jambonz/facade/ ./api/services/telephony/providers/jambonz/facade/
COPY --chown=65532:65532 deploy/onnuri-jambonz-facade/entrypoint.py /opt/recova/entrypoint.py
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip* /usr/local/bin/pip* \
    && test ! -e /srv/recova/api/services/telephony/onnuri_route_receipts.py \
    && ! grep -R -E 'onnuri_route_receipts|verify_route_chain' /srv/recova/api/services/telephony/providers/jambonz/facade

USER 65532:65532
ENTRYPOINT ["python", "/opt/recova/entrypoint.py"]

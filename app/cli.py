import argparse
import json
import logging
import secrets
import time
from datetime import datetime, timezone

import httpx

from app.application.execute import Execute
from app.infrastructure.cisa import CisaCrawler
from app.infrastructure.cognito import CognitoIdentity
from app.infrastructure.nvd import NvdClient
from app.infrastructure.smtp import SmtpSender
from app.settings import Settings, connect
from app.worker import tick


def main(argv=None):
    parser = argparse.ArgumentParser(description="Vigília — coleta e processamento independente")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bootstrap", help="Provisiona Cognito e administrador")
    collect = commands.add_parser("collect", help="Executa uma coleta independente do servidor web")
    collect.add_argument("--pages", type=int, default=0, help="0: catálogo completo")
    worker = commands.add_parser("worker", help="Processa programação, fila e SMTP")
    worker.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    settings = Settings()
    repo = connect(settings)
    repo.initialize()
    try:
        if args.command == "bootstrap":
            identity = CognitoIdentity(settings, repo)
            identity.provision()
            password = settings.admin_password or secrets.token_urlsafe(18) + "Aa1!"
            exists = False
            try:
                identity.client.admin_get_user(
                    UserPoolId=identity.config["pool_id"], Username=settings.admin_email
                )
                exists = True
            except identity.client.exceptions.UserNotFoundException:
                pass
            identity.bootstrap_admin(settings.admin_email, password)
            print(f"Administrador: {settings.admin_email}")
            if not exists:
                print(f"Senha inicial (guarde localmente): {password}")
            return 0
        with httpx.Client(
            timeout=45,
            follow_redirects=True,
            headers={"User-Agent": "Vigilia/0.1 educational-catalog-crawler"},
        ) as client:
            source, nvd, sender = (
                CisaCrawler(client),
                NvdClient(client, settings.nvd_api_key),
                SmtpSender(settings),
            )
            if args.command == "collect":
                if args.pages < 0:
                    parser.error("--pages deve ser >= 0")
                queued = repo.enqueue_run("cli", args.pages)
                job = repo.reserve_run(datetime.now(timezone.utc))
                if not job:
                    print("Coleta em andamento; solicitação ficou na fila: " + queued["id"])
                    return 0
                Execute(repo, source, nvd).run(job)
                result = next(run for run in repo.runs() if run["id"] == job["id"])
                print(json.dumps(result, default=str, ensure_ascii=False))
                return 1 if result["status"] == "failed" else 0
            while True:
                try:
                    logging.info("Processamento: %s", tick(repo, source, nvd, sender))
                except Exception:
                    logging.exception("Falha no processamento; nova tentativa no próximo ciclo")
                if args.once:
                    return 0
                time.sleep(5)
    finally:
        repo.db.client.close()


if __name__ == "__main__":
    raise SystemExit(main())

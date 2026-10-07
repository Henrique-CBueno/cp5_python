import smtplib
from email.message import EmailMessage


class SmtpSender:
    def __init__(self, settings):
        self.settings = settings

    def send(self, delivery):
        simulated = any(item.get("simulated") for item in delivery["items"])
        message = EmailMessage()
        message["From"] = "Vigília <alertas@vigilia.local>"
        message["To"] = delivery["email"]
        message["Subject"] = f"[Vigília]{' [DEMONSTRAÇÃO]' if simulated else ''} {delivery['name']} — {len(delivery['items'])} alerta(s)"
        lines = [f"Assinatura: {delivery['name']}", "Dados de CISA KEV: vulnerabilidades com exploração conhecida.", ""]
        for item in delivery["items"]:
            path = "/alertas" if item.get("simulated") else f"/vulnerabilidades/{item['cve_id']}"
            lines.extend([f"{item['cve_id']} — {item['vendor']} / {item['product']}", f"Evento: {'novo registro' if item['event'] == 'new' else 'registro alterado'}", item["title"], f"Ação recomendada pela fonte: {item['action']}", self.settings.public_url + path, ""])
        if simulated:
            lines.append("DEMONSTRAÇÃO: este evento é sintético e não representa uma vulnerabilidade real.")
        lines.append("Gerencie suas assinaturas em " + self.settings.public_url + "/alertas")
        message.set_content("\n".join(lines))
        with smtplib.SMTP(self.settings.smtp_host, self.settings.smtp_port, timeout=20) as smtp:
            smtp.send_message(message)

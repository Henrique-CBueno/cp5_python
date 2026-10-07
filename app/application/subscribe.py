from app.domain.subscription import Subscription


class Subscribe:
    def __init__(self, repository):
        self.repository = repository

    def save(
        self, owner: str, account_email: str, subscription: Subscription, subscription_id=None
    ):
        keys = {p["key"] for p in self.repository.products()}
        if any(key not in keys for key in subscription.products):
            raise ValueError("Selecione produtos existentes no catálogo")
        data = subscription.model_dump(mode="json")
        data["products"] = sorted(set(data["products"]))
        data["email"] = data["email"] or account_email
        return self.repository.save_subscription(owner, data, subscription_id)

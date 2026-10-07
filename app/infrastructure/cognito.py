import boto3
import jwt
from botocore.exceptions import ClientError


class CognitoIdentity:
    def __init__(self, settings, repository):
        self.settings, self.repository = settings, repository
        self.client = boto3.client("cognito-idp", endpoint_url=settings.cognito_endpoint, region_name="us-east-1", aws_access_key_id="local", aws_secret_access_key="local")
        self.config = repository.identity_config()
        self.jwks = None

    def provision(self):
        if self.config:
            return self.config
        pool = self.client.create_user_pool(PoolName="Vigilia", UsernameAttributes=["email"], AutoVerifiedAttributes=["email"])["UserPool"]
        app = self.client.create_user_pool_client(UserPoolId=pool["Id"], ClientName="VigiliaWeb", GenerateSecret=False, ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])["UserPoolClient"]
        self.client.create_group(UserPoolId=pool["Id"], GroupName="admin")
        self.config = {"pool_id": pool["Id"], "client_id": app["ClientId"]}
        self.repository.configure_identity(self.config)
        return self.config

    def signup(self, email, password):
        try:
            self.client.sign_up(ClientId=self.config["client_id"], Username=email, Password=password, UserAttributes=[{"Name": "email", "Value": email}])
        except ClientError as exc:
            raise ValueError("Não foi possível cadastrar. Verifique os dados ou se a conta já existe.") from exc

    def confirm(self, email, code):
        try:
            self.client.confirm_sign_up(ClientId=self.config["client_id"], Username=email, ConfirmationCode=code)
        except ClientError as exc:
            raise ValueError("Código inválido ou conta não disponível para confirmação.") from exc

    def login(self, email, password):
        try:
            result = self.client.initiate_auth(ClientId=self.config["client_id"], AuthFlow="USER_PASSWORD_AUTH", AuthParameters={"USERNAME": email, "PASSWORD": password})
            return result["AuthenticationResult"]["IdToken"]
        except ClientError as exc:
            raise ValueError("E-mail ou senha inválidos, ou conta ainda não confirmada.") from exc

    def validate(self, token):
        if not self.jwks:
            self.jwks = jwt.PyJWKClient(f"{self.settings.cognito_endpoint}/{self.config['pool_id']}/.well-known/jwks.json")
        key = self.jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=self.config["client_id"], issuer=f"{self.settings.cognito_issuer}/{self.config['pool_id']}", options={"require": ["exp", "iat", "sub", "aud", "iss"]})
        if claims.get("token_use") != "id":
            raise ValueError("Tipo de token inválido")
        return claims

    def bootstrap_admin(self, email, password):
        try:
            self.client.admin_get_user(UserPoolId=self.config["pool_id"], Username=email)
        except self.client.exceptions.UserNotFoundException:
            self.signup(email, password)
            self.client.admin_confirm_sign_up(UserPoolId=self.config["pool_id"], Username=email)
        self.client.admin_add_user_to_group(UserPoolId=self.config["pool_id"], Username=email, GroupName="admin")

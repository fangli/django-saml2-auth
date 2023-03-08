from django.db import models
from uuid import uuid4

class SamlMetaData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    updated_at = models.DateTimeField(
        auto_now=True,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    metadata_contents = models.TextField()
    email_domain = models.TextField(unique=True)

    enable_saml = models.BooleanField(blank=True, null=True,)
    enable_optional_saml = models.BooleanField(blank=True, null=True,)

    def __str__(self):
        return f"<SAML Metadata: {self.email_domain}>"

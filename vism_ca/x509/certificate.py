from dataclasses import dataclass, field

@dataclass
class ModuleArgsConfig:
    pass

@dataclass
class CertificateConfig:
    name: str
    module: str = None
    module_args: ModuleArgsConfig = None
    signed_by: str = None

    externally_managed: bool = False
    certificate_pem: str = None
    crl_pem: str = None

    def __post_init__(self):
        module_import = __import__(f'modules.{self.module}', fromlist=['ModuleArgsConfig'])
        self.module_args = module_import.ModuleArgsConfig(**self.module_args)
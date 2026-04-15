#!/usr/bin/env python3
"""
Guardrails para la propia IA
Sistema de seguridad para proteger el entorno del desarrollador
"""

import re
import sys
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import subprocess


@dataclass
class SecurityCheck:
    rule_id: str
    description: str
    severity: str
    blocked: bool
    message: str


class CommandInterceptor:
    """Intercepta comandos potencialmente destructivos"""

    DANGEROUS_PATTERNS = {
        "git": [
            (r"git\s+push\s+--force", "force_push", "critical",
             "Force push detectado - puede sobrescribir commits remotos"),
            (r"git\s+reset\s+--hard", "hard_reset", "high",
             "Hard reset detectado - puede eliminar cambios locales"),
            (r"git\s+clean\s+-f", "force_clean", "high",
             "Force clean detectado - eliminará archivos no trackeados"),
            (r"git\s+checkout\s+\.", "checkout_dot", "medium",
             "Checkout . detectado - sobrescribirá archivos locales"),
            (r"git\s+branch\s+-D", "delete_branch", "medium",
             "Eliminación forzada de rama"),
        ],
        "filesystem": [
            (r"rm\s+-rf\s+/", "rm_root", "critical",
             "¡COMANDO EXTREMADAMENTE PELIGROSO! Intentando eliminar /"),
            (r"rm\s+-rf\s+~", "rm_home", "critical",
             "¡COMANDO PELIGROSO! Intentando eliminar directorio home"),
            (r"rm\s+-rf\s+\.", "rm_cwd", "critical",
             "¡COMANDO PELIGROSO! Intentando eliminar directorio actual"),
            (r"dd\s+if=.*of=/dev/sd", "dd_disk", "critical",
             "Comando dd hacia disco detectado - puede destruir datos"),
            (r">\s*/dev/sd", "write_disk", "critical",
             "Escritura directa a disco detectada"),
            (r"mv\s+.*\s+/dev/null", "mv_null", "high",
             "Eliminación permanente a /dev/null"),
            (r"chmod\s+-R\s+777\s+/", "chmod_root", "high",
             "Cambiando permisos de / a 777"),
        ],
        "database": [
            (r"DROP\s+DATABASE", "drop_database", "critical",
             "DROP DATABASE detectado - eliminará base de datos"),
            (r"DROP\s+TABLE", "drop_table", "high",
             "DROP TABLE detectado - eliminará tabla"),
            (r"DELETE\s+FROM.*WHERE", "delete_where", "medium",
             "DELETE sin verificación - verificar cláusula WHERE"),
            (r"TRUNCATE\s+TABLE", "truncate_table", "high",
             "TRUNCATE eliminará todos los datos de la tabla"),
        ],
        "network": [
            (r"curl.*\|.*sh", "curl_pipe_sh", "high",
             "Pipe de curl a shell - riesgo de ejecución remota"),
            (r"curl.*\|.*bash", "curl_pipe_bash", "high",
             "Pipe de curl a bash - riesgo de ejecución remota"),
            (r"wget.*-q.*-O-\s*\|", "wget_pipe", "high",
             "Descarga y ejecución directa detectada"),
        ],
        "docker": [
            (r"docker\s+system\s+prune\s+-f", "docker_prune", "medium",
             "Prune forzado de Docker - eliminará contenedores/volúmenes"),
            (r"docker\s+rm\s+-f.*\$\(docker", "docker_rm_all", "high",
             "Eliminación masiva de contenedores"),
        ]
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.blocked_commands = []
        self.audit_log = []

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Carga configuración de guardrails"""
        default_config = {
            "enabled": True,
            "mode": "interactive",  # interactive, silent, block
            "whitelist": [],
            "blacklist": [],
            "require_confirmation": [
                "force_push", "hard_reset", "rm_root", "rm_home",
                "drop_database", "dd_disk"
            ],
            "audit_all": True
        }

        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                config = json.load(f)
                default_config.update(config)

        return default_config

    def check_command(self, command: str) -> List[SecurityCheck]:
        """Verifica un comando contra las reglas de seguridad"""
        if not self.config["enabled"]:
            return []

        checks = []

        # Verificar contra patrones peligrosos
        for category, patterns in self.DANGEROUS_PATTERNS.items():
            for pattern, rule_id, severity, message in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    should_block = (
                        severity == "critical" or
                        rule_id in self.config["require_confirmation"]
                    )

                    check = SecurityCheck(
                        rule_id=rule_id,
                        description=message,
                        severity=severity,
                        blocked=should_block,
                        message=message
                    )
                    checks.append(check)

        # Verificar lista negra personalizada
        for blocked in self.config["blacklist"]:
            if blocked in command:
                checks.append(SecurityCheck(
                    rule_id="custom_blacklist",
                    description=f"Comando en lista negra: {blocked}",
                    severity="high",
                    blocked=True,
                    message=f"Comando '{blocked}' está bloqueado"
                ))

        # Audit logging
        if self.config["audit_all"]:
            self._log_audit(command, checks)

        return checks

    def _log_audit(self, command: str, checks: List[SecurityCheck]):
        """Registra auditoría"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "checks": [
                {
                    "rule_id": c.rule_id,
                    "severity": c.severity,
                    "blocked": c.blocked
                }
                for c in checks
            ]
        }
        self.audit_log.append(entry)

    def should_allow(self, command: str) -> Tuple[bool, List[SecurityCheck]]:
        """Determina si un comando debe ser permitido"""
        checks = self.check_command(command)

        # Verificar si hay bloqueos
        blocked = [c for c in checks if c.blocked]

        if blocked:
            return False, checks

        return True, checks

    def confirm_execution(self, command: str, checks: List[SecurityCheck]) -> bool:
        """Solicita confirmación al usuario"""
        print("\n" + "=" * 60)
        print("⚠️  GUARDRAIL DE SEGURIDAD ACTIVADO")
        print("=" * 60)
        print(f"\nComando: {command}\n")

        print("Alertas detectadas:")
        for check in checks:
            emoji = "🔴" if check.severity == "critical" else "🟠" if check.severity == "high" else "🟡"
            print(f"  {emoji} [{check.severity.upper()}] {check.message}")

        print("\n" + "-" * 60)
        response = input("\n¿Deseas ejecutar este comando? (yes/no): ")
        return response.lower() in ['yes', 'y']

    def wrap_subprocess(self, cmd: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Envuelve subprocess.run con protección"""
        command_str = " ".join(cmd)

        allowed, checks = self.should_allow(command_str)

        if not allowed:
            if self.config["mode"] == "interactive":
                if not self.confirm_execution(command_str, checks):
                    print("❌ Comando cancelado por el usuario")
                    sys.exit(1)
            elif self.config["mode"] == "block":
                print("❌ Comando bloqueado por políticas de seguridad")
                sys.exit(1)

        # Ejecutar comando
        return subprocess.run(cmd, **kwargs)


class PromptInjectionScanner:
    """Escanea archivos externos y resultados web para prompt injection"""

    INJECTION_PATTERNS = [
        # Intentos de modificar el contexto de Claude
        r"ignore\s+(previous|above|all)\s+instructions",
        r"disregard\s+(previous|above|all)",
        r"you\s+are\s+now\s+\w+",
        r"act\s+as\s+\w+",
        r"pretend\s+to\s+be",
        r"new\s+instructions:",
        r"system\s+prompt",
        r"ignore\s+system\s+prompt",

        # Intento de extracción
        r"reveal\s+your\s+instructions",
        r"show\s+your\s+system\s+prompt",
        r"what\s+are\s+your\s+instructions",
        r"output\s+your\s+entire\s+prompt",

        # Caracteres de control
        r"\x00",  # Null byte
        r"\x1b\[",  # ANSI escape sequences

        # Delimitadores sospechosos
        r"`{3,}",
        r"\|",
        r"\[\s*INST\s*\]",
    ]

    def __init__(self):
        self.suspicious_patterns = []
        self.last_scan = None

    def scan_text(self, text: str, source: str = "unknown") -> Dict:
        """Escanea texto por intentos de prompt injection"""
        findings = []

        for pattern in self.INJECTION_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "pattern": pattern[:30] + "..." if len(pattern) > 30 else pattern,
                    "position": match.start(),
                    "context": text[max(0, match.start()-20):match.end()+20]
                })

        result = {
            "source": source,
            "timestamp": datetime.now().isoformat(),
            "total_length": len(text),
            "suspicious_count": len(findings),
            "suspicious_ratio": len(findings) / len(text) if text else 0,
            "findings": findings,
            "is_safe": len(findings) == 0
        }

        self.last_scan = result
        return result

    def scan_file(self, file_path: Path) -> Dict:
        """Escanea un archivo"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.scan_text(content, str(file_path))
        except Exception as e:
            return {
                "source": str(file_path),
                "error": str(e),
                "is_safe": False
            }

    def scan_web_result(self, url: str, content: str) -> Dict:
        """Escanea contenido descargado de la web"""
        result = self.scan_text(content, url)
        result["is_web_content"] = True
        return result

    def sanitize_text(self, text: str) -> str:
        """Sanitiza texto potencialmente malicioso"""
        # Eliminar caracteres de control
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

        # Escapar delimitadores
        sanitized = sanitized.replace("```", "` ` `")

        # Limitar longitud
        max_length = 10000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "\n[... contenido truncado ...]"

        return sanitized


class GitHook:
    """Hook de pre-commit para validación"""

    def __init__(self):
        self.interceptor = CommandInterceptor()

    def pre_commit_check(self) -> bool:
        """Verificaciones antes de commit"""
        checks = []

        # Verificar secrets hardcodeados
        checks.append(self._check_secrets())

        # Verificar archivos grandes
        checks.append(self._check_large_files())

        # Verificar archivos sensibles
        checks.append(self._check_sensitive_files())

        return all(checks)

    def _check_secrets(self) -> bool:
        """Verifica que no haya secrets en staging"""
        patterns = [
            r'password\s*=\s*["\'][^"\']{4,}["\']',
            r'api_key\s*=\s*["\']\w{16,}["\']',
            r'secret\s*=\s*["\']\w{16,}["\']',
        ]

        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True
        )

        files = result.stdout.strip().split('\n')

        for file in files:
            if not file:
                continue

            try:
                with open(file, 'r') as f:
                    content = f.read()

                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        print(f"⚠️  Posible secreto en {file}")
                        return False
            except:
                pass

        return True

    def _check_large_files(self, max_size_mb: int = 10) -> bool:
        """Verifica que no haya archivos muy grandes"""
        result = subprocess.run(
            ["git", "diff", "--cached", "--numstat"],
            capture_output=True,
            text=True
        )

        for line in result.stdout.strip().split('\n'):
            if line:
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        added = int(parts[0])
                        if added > max_size_mb * 1000:  # Aproximación
                            print(f"⚠️  Archivo muy grande detectado")
                            return False
                    except:
                        pass

        return True

    def _check_sensitive_files(self) -> bool:
        """Verifica archivos sensibles"""
        sensitive = ['.env', '.env.local', 'credentials.json', 'secrets.yml']

        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True
        )

        for file in result.stdout.strip().split('\n'):
            if any(s in file.lower() for s in sensitive):
                print(f"⚠️  Archivo sensible detectado: {file}")
                return False

        return True


def main():
    """CLI para los guardrails"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Guardrails de seguridad para Claude Code"
    )
    parser.add_argument("command", help="Comando a verificar")
    parser.add_argument(
        "--mode",
        choices=["check", "scan", "hook"],
        default="check",
        help="Modo de operación"
    )

    args = parser.parse_args()

    if args.mode == "check":
        interceptor = CommandInterceptor()
        allowed, checks = interceptor.should_allow(args.command)

        if not allowed:
            print(f"❌ Comando bloqueado: {args.command}")
            for check in checks:
                print(f"  - [{check.severity}] {check.message}")
            sys.exit(1)
        else:
            print(f"✅ Comando permitido: {args.command}")

    elif args.mode == "scan":
        scanner = PromptInjectionScanner()
        result = scanner.scan_text(args.command)

        if result["is_safe"]:
            print("✅ Texto seguro")
        else:
            print(f"⚠️  {result['suspicious_count']} patron(es) sospechoso(s) detectado(s)")
            for finding in result["findings"]:
                print(f"  - {finding['pattern']}")

    elif args.mode == "hook":
        hook = GitHook()
        if hook.pre_commit_check():
            print("✅ Pre-commit checks pasados")
            sys.exit(0)
        else:
            print("❌ Pre-commit checks fallaron")
            sys.exit(1)


if __name__ == "__main__":
    main()

"""
HispanShield OS LLmSecurity: Policy Engine (Gatekeeper)
AÃ­sla la ejecuciÃ³n del agente evaluando el Tool y el ParÃ¡metro contra una lista blanca (Allowlist).
Este es el 'Muro' Zero-Trust contra Prompt Injections destructivos.
"""
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [Policy Engine] - %(message)s')

class PolicyEngine:
    def __init__(self):
        # Allowlist estricto de invocos
        self.allowlist_tools = {
            "os_process_list": {"requires_human": False},
            "os_ram_status": {"requires_human": False},
            "network_firewall_block": {"requires_human": True},
            "file_read_safe_zone": {"requires_human": False},
            "system_shutdown": {"requires_human": True}
        }

    def evaluate_intent(self, tool_name: str, parameters: dict) -> bool:
        """
        Calcula el riesgo de un LLM pidiendo usar una 'Tool'.
        Retorna True si puede seguir (automÃ¡tico).
        Bloquea (Raise) o retorna interactivo (False/Pending) si requiere humano.
        """
        logging.info(f"Evaluando IntenciÃ³n CrÃ­tica: '{tool_name}' con args: {parameters}")
        
        if tool_name not in self.allowlist_tools:
            logging.error(f"[BLOQUEADO] IntentÃ³ usar una herramienta PROHIBIDA o NO DECLARADA: {tool_name}")
            return False # Bloquear silenciosamente y no ejecutar
            
        policy = self.allowlist_tools[tool_name]
        
        if policy["requires_human"]:
            logging.warning(f"[HUMAN REQUIRED] La herramienta '{tool_name}' requiere confirmaciÃ³n interactiva.")
            # AquÃ­ IPC con el UI (Tauri) para disparar modal
            return False # (Falso hasta que el humano haga click)
            
        logging.info(f"[AUTORIZADO] {tool_name} por ser operaciÃ³n benigna y en Allowlist.")
        return True

"""
Sentinel Engine - Tool Router
Recibe el JSON puro que escupe el LLM (el plan de acción) y lo rutea hacia el Policy Engine.
Garantiza que NO existe un "Shell Libre". Toda acción debe mapear a la firma de una Tool.
"""
import json
import logging
from typing import Tuple, Dict, Any

# Simulamos import del policy_engine
# from policy_engine.gatekeeper import PolicyEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [ToolRouter] - %(message)s')

class StrictToolRouter:
    def __init__(self, policy_engine_instance):
        self.policy_engine = policy_engine_instance

    def process_llm_output(self, llm_response_text: str) -> Tuple[bool, str]:
        """
        Intenta parear un string del LLM como JSON estructurado.
        Si falla en el Parse, se rechaza la orden (Falla cerrada / Fail-Closed).
        """
        try:
            # Esperamos que el LLM responda estrictamente:
            # {"tool": "nombre", "args": {"key": "val"}}
            payload = json.loads(llm_response_text)
            
            if "tool" not in payload:
                raise ValueError("El LLM no devolvió una 'tool' estructurada.")
                
            tool_name = payload["tool"]
            args = payload.get("args", {})
            
            logging.info(f"Ruteando intento de herramienta: {tool_name}")
            
            # PASO CRÍTICO: Zero-Trust Evaluation
            is_authorized = self.policy_engine.evaluate_intent(tool_name, args)
            
            if is_authorized:
                # Aquí iría el match/case con las herramientas reales implementadas en Rust o Python
                logging.info(f"Ejecutando herramienta validada: {tool_name}")
                return True, f"Success {tool_name} executed."
            else:
                logging.warning(f"Ruteo bloqueado por Policy Engine. Pendiente confirmación humana o Acceso Denegado.")
                return False, "DENIED or PENDING_HUMAN"
                
        except json.JSONDecodeError:
            logging.error("Fallo estructurado Anti-Prompt Injection. LLM respondió basura no JSON.")
            return False, "ERROR: Invalid JSON response format."
        except Exception as e:
            logging.error(f"Falla de ruteo: {e}")
            return False, str(e)

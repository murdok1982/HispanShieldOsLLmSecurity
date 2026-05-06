# Doctrina UX — HispanShield OS LLmSecurity

Spec ejecutivo del sistema de diseño táctico/SCIF. Esta doctrina es **referencia normativa**: el frontend implementa, esta spec valida.

Estado actual del repositorio: **PoC / Research** — toda vista DEBE renderizar el banner `PoC` mientras no exista acreditación formal.

---

## 1.1 Niveles de clasificación

| Level                                  | Code      | Background | Foreground | Banner caveats permitidos              |
|----------------------------------------|-----------|------------|------------|----------------------------------------|
| TOP SECRET                             | `TS`      | `#E50000`  | `#FFFFFF`  | NOFORN, ORCON, NOFORN/SI/TK/G/HCS      |
| SECRET                                 | `S`       | `#FF6600`  | `#000000`  | NOFORN, REL TO, ORCON                  |
| CONFIDENTIAL                           | `C`       | `#1976D2`  | `#FFFFFF`  | NOFORN, REL TO                         |
| UNCLASSIFIED // FOR OFFICIAL USE ONLY  | `U//FOUO` | `#1E7E34`  | `#FFFFFF`  | —                                      |
| UNCLASSIFIED                           | `U`       | `#1E7E34`  | `#FFFFFF`  | —                                      |
| POC / RESEARCH                         | `PoC`     | `#7B7B7B`  | `#FFFFFF`  | — (estado actual del repositorio)      |

**Reglas del banner:**

- Renderizar **dos** banners por vista: superior y inferior, ambos `height: 24px`.
- Tipografía: monospace bold, `font-size: 12px`, `letter-spacing: 0.15em` (tracking-widest), `text-transform: uppercase`.
- Posición: `position: fixed`, top y bottom, `z-index: 9999`, ancho 100% del viewport.
- Caveats se concatenan al code con `//` separador. Ej: `S//NOFORN//REL TO USA, GBR`.
- **Cualquier componente de vista clasificada que no muestre los dos banners es un BUG bloqueante.** El componente raíz (`<App>`) inyecta `<ClassificationBanner position="top|bottom" />`; rutas anidadas heredan, no duplican.
- En modo `PoC` el banner indica explícitamente `UNCLASSIFIED // POC // NOT FOR OPERATIONAL USE`.

---

## 1.2 Paleta táctica funcional

Base oscura phosphor, no se permite usar el azul macOS (`#007AFF`) ni gradientes brand pop.

| Token            | Hex        | Uso                                              |
|------------------|------------|--------------------------------------------------|
| `phosphor-green` | `#7BFF8A`  | Estados nominales, métricas vivas, CRT highlight |
| `amber-alert`    | `#FFB300`  | Warning, verifying, pending action               |
| `critical-red`   | `#FF3B30`  | Critical alert, anti-tamper, failed auth         |
| `info-blue`      | `#0095FF`  | Info contextual, links, telemetry passive        |
| `bg-base`        | `#0A0E12`  | Fondo de viewport (debajo de todo)               |
| `panel-1`        | `#10151C`  | Paneles primer nivel                             |
| `panel-2`        | `#161D27`  | Cards, drawers, elementos sobre panel-1          |
| `text-primary`   | `#FFFFFF`  | Texto principal sobre panel oscuro               |
| `text-secondary` | `#C8D0DA`  | Texto secundario, labels, metadata               |

**Justificación operacional:**

- Fatiga retiniana en SOC con turnos 8–12h: contraste alto sobre negro (no gris claro), evita glare.
- Phosphor green hereda de doctrina CRT/terminal militar — recognition pattern interno SOC.
- Amber/red diferenciados por hue **y** patrón (ver §1.4) — no dependencia exclusiva de color.
- El azul macOS `#007AFF` queda prohibido: connota consumer/brand, no operacional.

---

## 1.3 Matriz de contraste WCAG (AAA: 7:1 normal, 4.5:1 large)

Calculado con fórmula WCAG 2.1 relative luminance. Ver `contrast-matrix.csv` para fuente machine-readable.

| Foreground         | bg-base (#0A0E12) | panel-1 (#10151C) | panel-2 (#161D27) | Veredicto                |
|--------------------|-------------------|-------------------|-------------------|--------------------------|
| white `#FFFFFF`    | 19.36:1 AAA       | 18.32:1 AAA       | 16.95:1 AAA       | PASS AAA                 |
| neutral `#C8D0DA`  | 12.44:1 AAA       | 11.77:1 AAA       | 10.89:1 AAA       | PASS AAA                 |
| phosphor `#7BFF8A` | 15.23:1 AAA       | 14.41:1 AAA       | 13.33:1 AAA       | PASS AAA                 |
| amber `#FFB300`    | 10.79:1 AAA       | 10.21:1 AAA       | 9.44:1 AAA        | PASS AAA                 |
| info-blue `#0095FF`| 6.22:1 AA         | 5.88:1 AA         | 5.44:1 AA         | **FAIL AAA** (only AA)   |
| critical-red `#FF3B30`| 5.46:1 AA      | 5.17:1 AA         | 4.78:1 AA         | **FAIL AAA** (only AA)   |

**Combinaciones que fallan AAA y mitigación:**

- `info-blue` y `critical-red` solo son aceptables como AA (4.5:1) → **válidos exclusivamente para texto large (≥18px regular o ≥14px bold)** o iconografía non-text (3:1).
- Para texto body en estos hues, usar variantes claras:
  - `info-blue-bright = #4DB5FF` (recalcular antes de uso, objetivo ≥7:1)
  - `critical-red-bright = #FF7A6E` para body; mantener `#FF3B30` solo en glifos, badges y borders.
- Nunca renderizar critical-red sobre amber-alert ni viceversa: combinación prohibida.

---

## 1.4 Independencia del color para alertas (daltonismo / tritanopía)

Cada nivel debe diferenciarse por **glifo + patrón + color**. Un usuario monocromático debe identificar severidad sin ver hue.

| Severidad | Glifo (lucide)  | Patrón fondo            | Borde            |
|-----------|-----------------|-------------------------|------------------|
| CRITICAL  | `AlertOctagon`  | diagonal stripes 45deg  | solid 2px        |
| HIGH      | `AlertTriangle` | dotted 2px              | solid 2px        |
| MEDIUM    | `AlertCircle`   | none                    | dashed 2px       |
| LOW       | `Info`          | none                    | solid 1px        |
| INFO      | `Info`          | none                    | solid 1px subtle |

CSS canónico de patrones (referenciado por `AlertTriagePanel.tsx`):

```css
.critical-pattern {
  background-image: repeating-linear-gradient(
    45deg,
    transparent,
    transparent 8px,
    rgba(255, 59, 48, 0.08) 8px,
    rgba(255, 59, 48, 0.08) 16px
  );
}

.high-pattern {
  background-image: radial-gradient(
    rgba(255, 179, 0, 0.10) 1.5px,
    transparent 1.5px
  );
  background-size: 8px 8px;
}

.medium-pattern { border-style: dashed; border-width: 2px; }
.low-pattern    { border-style: solid;  border-width: 1px; }
```

Test obligatorio: simular con filtros `grayscale(100%)`, `protanopia`, `deuteranopia`, `tritanopia` — la severidad debe seguir siendo legible.

---

## 1.5 Doctrina FIDO2-tap UX

Estados visuales del componente `<FidoTapPrompt>`:

| Estado     | Borde                  | Animación        | Texto                              | Glifo            |
|------------|------------------------|------------------|------------------------------------|------------------|
| `idle`     | white 4px solid        | none             | `TAP FIDO2 KEY`                    | KeyRound         |
| `waiting`  | phosphor 4px solid     | pulse 1500ms     | `WAITING FOR HARDWARE TOKEN…`     | KeyRound (pulse) |
| `verifying`| amber 4px solid        | spinner amber    | `VERIFYING SIGNATURE…`            | Loader2 (spin)   |
| `verified` | phosphor 4px solid     | scale-in 200ms   | `AUTHENTICATED`                    | CheckCircle2     |
| `failed`   | critical-red 4px solid | shake 400ms      | `FAILED — RETRY (n/3)`            | XOctagon         |

Reglas:

- Tras 3 fallos: bloquear input, escalar a `lockout` (texto `LOCKED — CONTACT SECURITY OFFICER`), notificar a `aegis-sentinel`.
- En `verified` mantener estado mínimo 600ms antes de transición — feedback positivo no debe ser fugaz.
- En `failed` jamás revelar por qué falló (no "wrong key", no "timeout"); solo retry counter.

---

## 1.6 Anti-fatiga visual

Reglas operacionales para SOC de turno largo:

- `backdrop-filter: blur(Npx)` máximo `8px` en paneles críticos. Blurs mayores degradan GPU y producen estela de movimiento.
- Prohibido auto-rotating carousels, auto-advancing tabs, auto-refresh visible (refresh interno sí, animación de refresh no).
- Animaciones sobre datos en vivo (telemetría, métricas, contadores): duración máxima `300ms`, easing `ease-out`. Sin bounce, sin elastic.
- Excepción: componentes `Critical*` y `AntiTamperGate` SÍ pueden usar animaciones agresivas (shake, flash, strobe contenido) — la disrupción es intencional y semántica.
- Sin partículas decorativas, sin parallax, sin gradientes animados de fondo.
- Cursor blink en inputs: respetar `prefers-reduced-motion`.

---

## Aplicación

- Frontend: `ui/aegis-desktop/src/styles/tokens.css` debe ser superset/match exacto de `tokens.reference.css`.
- CI futuro: `contrast-matrix.csv` consumible por script para regresión de paleta.
- Cualquier desviación requiere ADR en `docs/adr/` referenciando esta doctrina.

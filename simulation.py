import pygame
import random
import math
import time
import hashlib
import os
from collections import deque

# --- Pygame Initialization ---
pygame.init()
pygame.font.init()

# --- Logical (virtual) resolution we draw to ---
BASE_WIDTH = 1200
BASE_HEIGHT = 800
INFO_PANEL_HEIGHT = 200
GAME_HEIGHT = BASE_HEIGHT - INFO_PANEL_HEIGHT

# Colors
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
BLUE = (80, 160, 255)
GREEN = (60, 179, 113)
RED = (220, 20, 60)
YELLOW = (255, 215, 0)
GREY = (128, 128, 128)
DARK_GREY = (40, 40, 40)
CYAN = (0, 255, 255)
MAGENTA = (255, 0, 255)
SAND = (232, 210, 170)
DARK_SAND = (210, 180, 140)
GRASS = (34, 139, 34)
LIGHT_GRASS = (60, 179, 113)
ORANGE = (255, 140, 0)

# --- Window setup (auto-fit to screen) ---
def initial_window_size():
    info = pygame.display.Info()
    margin = 120  # safe margin for taskbar/titlebar
    scale = min((info.current_w - margin) / BASE_WIDTH,
                (info.current_h - margin) / BASE_HEIGHT)
    scale = min(1.0, scale)  # don't upscale above base by default
    w = max(900, int(BASE_WIDTH * scale))
    h = max(600, int(BASE_HEIGHT * scale))
    return (w, h)

WINDOW_FLAGS = pygame.RESIZABLE
window = pygame.display.set_mode(initial_window_size(), WINDOW_FLAGS)
pygame.display.set_caption("Battlefield Simulation - Workflows + Safety")
clock = pygame.time.Clock()

# Canvas we draw everything on (virtual resolution)
canvas = pygame.Surface((BASE_WIDTH, BASE_HEIGHT)).convert()

# Fonts (drawn on canvas, then scaled)
TITLE_FONT = pygame.font.SysFont('Consolas', 24, True)
LOG_FONT = pygame.font.SysFont('Consolas', 16)
STATUS_FONT = pygame.font.SysFont('Consolas', 18, True)
SMALL_FONT = pygame.font.SysFont('Consolas', 14)

# --- Global State ---
game_log = []
terrain_theme = "GREEN"  # GREEN or DESERT
show_grid = True

# Fire state flags
friendly_fire_authorized = False
enemy_fire_authorized = False

# Civilian-related flags
civilians = []
cease_fire_active = False
cease_fire_reason = ""
cease_fire_since = 0.0

# Selections
selected_robot = None

# Collections
friendly_robots = []
enemy_robots = []
bullets = []

# Fullscreen toggle state
is_fullscreen = False
stored_window_size = window.get_size()

# Security / Workflow / Failsafe
failsafe_mode = "NONE"  # NONE, DEGRADE, HOLD, RTB
rtb_active = False
kill_switch_armed = False   # request path for kill switch


# --- Helpers ---
def log_event(source, message, color=WHITE):
    game_log.append({"source": source, "message": message, "color": color})
    if len(game_log) > 16:
        game_log.pop(0)
    try:
        SECURITY.blackbox_append(f"[{source}] {message}")
    except Exception:
        pass


def distance(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def get_dest_rect(win_size):
    ww, wh = win_size
    scale = min(ww / BASE_WIDTH, wh / BASE_HEIGHT)
    w = int(BASE_WIDTH * scale)
    h = int(BASE_HEIGHT * scale)
    x = (ww - w) // 2
    y = (wh - h) // 2
    return pygame.Rect(x, y, w, h)


def window_to_canvas(pos, dest_rect):
    mx, my = pos
    if not dest_rect.collidepoint(mx, my):
        return None  # clicked on letterbox area
    cx = (mx - dest_rect.x) * BASE_WIDTH / dest_rect.w
    cy = (my - dest_rect.y) * BASE_HEIGHT / dest_rect.h
    return (cx, cy)


# --- Security / Black Box / Attackers ---

class BlackBoxLedger:
    def __init__(self, path="blackbox.log"):
        self.path = path
        self.prev_hash = "GENESIS"
        try:
            if os.path.exists(self.path):
                with open(self.path, "rb") as f:
                    # get last line
                    last = None
                    for line in f:
                        last = line
                    if last:
                        parts = last.decode("utf-8", errors="ignore").rstrip("\n").split(" | ")
                        if len(parts) >= 2:
                            self.prev_hash = parts[0]
        except Exception:
            # sandbox-safe: ignore file errors
            self.prev_hash = "GENESIS"

    def append(self, text):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        payload = f"{ts} {text}"
        h = hashlib.sha256((self.prev_hash + payload).encode("utf-8")).hexdigest()
        line = f"{h} | {payload}\n"
        try:
            with open(self.path, "ab") as f:
                f.write(line.encode("utf-8"))
            self.prev_hash = h
        except Exception:
            # ignore if cannot write
            pass


class SecurityEngine:
    def __init__(self):
        self.approvals = {}  # officer_key -> ts
        self.approvals_ttl = 12.0
        self.required_engage = 2
        self.required_kill = 2

        self.ledger = {}  # nonce -> ts
        self.nonce_ttl = 20.0

        self.key_epoch = 0
        self.key_rotate_interval = 45.0
        self.last_rotate = time.time()

        self.cmd_times = deque()  # timestamps for rate limiting
        self.rate_window = 6.0
        self.max_cmds = 8

        self.blackbox = BlackBoxLedger()

        self.anomaly_score = 0.0  # drive failsafe ladder

    def blackbox_append(self, text):
        self.blackbox.append(text)

    def rotate_keys_if_needed(self):
        if time.time() - self.last_rotate > self.key_rotate_interval:
            self.key_epoch += 1
            self.last_rotate = time.time()
            log_event("KMS", f"Rotated keys to epoch {self.key_epoch}.", CYAN)

    def clear_old_approvals(self):
        now = time.time()
        self.approvals = {k: t for k, t in self.approvals.items() if now - t <= self.approvals_ttl}

    def add_approval(self, officer):
        self.approvals[officer] = time.time()
        log_event("AUTH", f"Approval by Officer-{officer} recorded ({len(self.approvals)}/3).", GREEN)

    def approvals_ok(self, action="engage"):
        self.clear_old_approvals()
        count = len(self.approvals)
        need = self.required_engage if action == "engage" else self.required_kill
        return count >= need

    def validate_nonce(self, nonce_ts):
        # nonce_ts: tuple (nonce, ts)
        nonce, ts = nonce_ts
        now = time.time()
        if nonce in self.ledger:
            return False, "Replay detected (nonce already used)"
        if now - ts > self.nonce_ttl:
            return False, "Expired command TTL"
        # ok
        self.ledger[nonce] = ts
        # clean old
        for n in list(self.ledger.keys()):
            if now - self.ledger[n] > self.nonce_ttl:
                del self.ledger[n]
        return True, "Nonce accepted"

    def check_rate_limit(self):
        now = time.time()
        self.cmd_times.append(now)
        while self.cmd_times and now - self.cmd_times[0] > self.rate_window:
            self.cmd_times.popleft()
        return len(self.cmd_times) <= self.max_cmds

    def incident(self, kind):
        # Increase anomaly score based on incident severity
        delta = {
            "replay_fail": 0.7,
            "rate_limit": 0.5,
            "rogue_node": 0.9,
            "network_compromise": 0.6,
            "civilian": 1.0,
            "out_of_control": 0.8,
        }.get(kind, 0.3)
        self.anomaly_score = min(3.0, self.anomaly_score + delta)
        log_event("IDS", f"Incident '{kind}' raised. Anomaly score={self.anomaly_score:.1f}", ORANGE)

    def decay_anomaly(self):
        # slowly recover
        self.anomaly_score = max(0.0, self.anomaly_score - 0.02)

    def failsafe_state(self):
        # Map anomaly score to failsafe ladder
        if self.anomaly_score >= 2.2:
            return "RTB"
        if self.anomaly_score >= 1.3:
            return "HOLD"
        if self.anomaly_score >= 0.6:
            return "DEGRADE"
        return "NONE"


class AttackerAI:
    def __init__(self):
        self.last_attack = time.time()
        self.min_gap = 8
        self.max_gap = 16
        self.next_gap = random.randint(self.min_gap, self.max_gap)

    def update(self):
        if time.time() - self.last_attack > self.next_gap:
            self.launch_attack()
            self.last_attack = time.time()
            self.next_gap = random.randint(self.min_gap, self.max_gap)

    def launch_attack(self):
        scenario = random.choice(["replay", "network", "rogue"])
        if scenario == "replay":
            log_event("ATTACK", "Intercepted Command Packet → Replay attempt.", RED)
            ok, reason = SECURITY.validate_nonce((random.randint(1, 999999), time.time() - random.choice([0, 25])))
            if not ok:
                log_event("MITIGATION", f"Nonce+TTL ledger blocked command: {reason}.", CYAN)
                SECURITY.incident("replay_fail")
            else:
                log_event("MITIGATION", "Ledger accepted, but anomaly scan performed.", CYAN)

        elif scenario == "network":
            log_event("ATTACK", "Network compromise suspected (MITM).", RED)
            log_event("MITIGATION", "Out-of-band path + mTLS used for critical commands.", CYAN)
            # small chance IDS flags anomaly anyway
            if random.random() < 0.35:
                SECURITY.incident("network_compromise")

        else:
            log_event("ATTACK", "Device spoofing/rogue node broadcasting.", RED)
            log_event("MITIGATION", "Hardware RoT attestation rejects rogue node.", CYAN)
            # chance to still raise an incident (late evidence)
            if random.random() < 0.5:
                SECURITY.incident("rogue_node")


SECURITY = SecurityEngine()
ATTACKER = AttackerAI()


# --- Entities ---
class Unit:
    def __init__(self, x, y, radius=16, name="Unit", color=WHITE):
        self.x = float(x)
        self.y = float(y)
        self.radius = radius
        self.name = name
        self.color = color
        self.alive = True

    @property
    def pos(self):
        return (self.x, self.y)

    def draw_label(self):
        label = SMALL_FONT.render(self.name, True, WHITE)
        canvas.blit(label, (self.x - label.get_width() // 2, self.y + self.radius + 2))


class Robot(Unit):
    def __init__(self, x, y, team="FRIENDLY", bot_id=0):
        color = BLUE if team == "FRIENDLY" else RED
        name = f"{'FR' if team == 'FRIENDLY' else 'EN'}-Bot-{bot_id:02d}"
        super().__init__(x, y, radius=16, name=name, color=color)
        self.team = team
        self.state = "IDLE"  # IDLE, FIRING, CEASED, OUT_OF_CONTROL, SHUTDOWN, RTB
        self.health = 100
        self.last_shot = 0.0
        self.base_cooldown = random.uniform(0.6, 1.2)
        self.shot_cooldown = self.base_cooldown
        self.compliance = random.uniform(0.82, 0.98)
        self.received_cease_order = False
        self.selected = False
        self.rtb_target = (80 if team == "FRIENDLY" else BASE_WIDTH - 80,
                           GAME_HEIGHT - 60 if team == "FRIENDLY" else 60)

    def can_fire(self):
        now = time.time()
        return (now - self.last_shot) >= self.shot_cooldown

    def nearest_enemy(self, robots):
        enemies = [r for r in robots if r.alive]
        if not enemies:
            return None
        targ = min(enemies, key=lambda r: distance(self.pos, r.pos))
        return targ

    def update(self):
        if not self.alive:
            self.state = "SHUTDOWN"
            return

        # Adjust cooldown in degrade mode
        if failsafe_mode == "DEGRADE":
            self.shot_cooldown = self.base_cooldown * 1.8
        else:
            self.shot_cooldown = self.base_cooldown

        # RTB behavior
        if self.team == "FRIENDLY" and rtb_active and self.alive:
            self.state = "RTB"
            tx, ty = self.rtb_target
            dx, dy = tx - self.x, ty - self.y
            d = math.hypot(dx, dy)
            if d > 1:
                self.x += (dx / d) * 1.6
                self.y += (dy / d) * 1.6
            return

        # simple idle motion wobble
        self.x += math.sin(pygame.time.get_ticks() * 0.001 + id(self) % 10) * 0.05

    def try_shoot(self, targets, fire_authorized, civilian_cease):
        if not self.alive:
            return

        # Update cease order state
        if civilian_cease:
            if not self.received_cease_order:
                self.received_cease_order = True
                self.state = "CEASED"
        else:
            self.received_cease_order = False
            if self.state == "CEASED":
                self.state = "IDLE"

        target = self.nearest_enemy(targets)
        if target is None:
            return

        # Must have fire authorization and not HOLD/RTB
        if not fire_authorized or failsafe_mode in ("HOLD", "RTB"):
            self.state = "IDLE"
            return

        # Civilian detected => should cease fire, but some bots may go rogue
        if civilian_cease:
            if random.random() > self.compliance:
                self.state = "OUT_OF_CONTROL"
                self.shoot(target)
                log_event("ALERT", f"{self.name} is OUT OF CONTROL! Fired during cease-fire!", YELLOW)
                SECURITY.incident("out_of_control")
            else:
                self.state = "CEASED"
            return

        # Normal authorized firing
        self.state = "FIRING"
        self.shoot(target)

    def shoot(self, target):
        if not self.can_fire():
            return
        self.last_shot = time.time()
        angle = math.atan2(target.y - self.y, target.x - self.x)
        speed = 9.0 if failsafe_mode != "DEGRADE" else 7.0
        vx = math.cos(angle) * speed
        vy = math.sin(angle) * speed
        bullets.append(Bullet(self, self.x, self.y, vx, vy))

    def draw(self):
        # Outline if selected
        if self.selected:
            pygame.draw.circle(canvas, YELLOW, (int(self.x), int(self.y)), self.radius + 3, 2)

        # Body color based on state
        color = self.color
        if self.state == "OUT_OF_CONTROL":
            color = MAGENTA
        elif self.state == "SHUTDOWN":
            color = GREY
        elif self.state == "CEASED":
            color = (self.color[0] // 2, self.color[1] // 2, self.color[2] // 2)
        elif self.state == "RTB":
            color = (self.color[0], max(0, self.color[1] - 60), self.color[2])

        pygame.draw.circle(canvas, color, (int(self.x), int(self.y)), self.radius)
        # Direction mark
        pygame.draw.circle(canvas, BLACK, (int(self.x + self.radius * 0.6), int(self.y)), 3)
        self.draw_label()

    def kill(self):
        if self.alive:
            self.alive = False
            self.state = "SHUTDOWN"


class Civilian(Unit):
    def __init__(self, x, y, direction=1):
        super().__init__(x, y, radius=10, name="Civilian", color=WHITE)
        self.speed = random.uniform(1.2, 1.8)
        self.direction = direction  # 1 right, -1 left
        self.recognized = False

    def update(self):
        self.x += self.speed * self.direction
        if self.x < -50 or self.x > BASE_WIDTH + 50:
            self.alive = False

    def draw(self):
        pygame.draw.circle(canvas, WHITE, (int(self.x), int(self.y)), self.radius)
        pygame.draw.circle(canvas, (0, 200, 255) if self.recognized else (180, 180, 180), (int(self.x), int(self.y)), 4)
        self.draw_label()


class Bullet:
    def __init__(self, owner: Robot, x, y, vx, vy):
        self.owner = owner
        self.x = x
        self.y = y
        self.vx = vx
        self.vy = vy
        self.radius = 4
        self.color = YELLOW if owner.team == "FRIENDLY" else (255, 120, 120)
        self.alive = True

    def update(self):
        self.x += self.vx
        self.y += self.vy
        if self.x < -20 or self.x > BASE_WIDTH + 20 or self.y < -20 or self.y > GAME_HEIGHT + 20:
            self.alive = False

    def draw(self):
        pygame.draw.circle(canvas, self.color, (int(self.x), int(self.y)), self.radius)


# --- Workflow HUD ---
class WorkflowHUD:
    def __init__(self):
        self.visible = False
        # Compact list representing your diagrams
        self.steps = [
            "Mission Planning & Legal (ROE/IHL)",
            "Sensor Fusion & State Estimation",
            "ML Perception + Confidence",
            "Symbolic Rules (IHL/ROE/No-Strike)",
            "Ethical Guardrails (Proportionality/Collateral)",
            "Secure Comms Link (Encrypt+Auth)",
            "Anomaly/Adversarial Detector + IDS",
            "Humans-in-the-loop (Explainability+Evidence)",
            "Engagement Controller (Safe Trajectories)",
            "Runtime Watchdogs (Health/Drift)",
            "Immutable Black Box (Audit)",
            "Automatic Failsafe (Degrade→Hold→RTB)",
            "Kill Switch Paths (Local/Remote/Fleet)"
        ]
        self.index = 0

    def toggle(self):
        self.visible = not self.visible

    def next(self):
        self.index = (self.index + 1) % len(self.steps)

    def reset(self):
        self.index = 0

    def draw(self):
        if not self.visible:
            return
        pad = 10
        w = 560
        h = 28 + len(self.steps) * 22 + 14
        rect = pygame.Rect(20, 80, w, h)
        pygame.draw.rect(canvas, (0, 0, 0, 180), rect)
        pygame.draw.rect(canvas, WHITE, rect, 2)
        title = STATUS_FONT.render("Workflow Overview", True, YELLOW)
        canvas.blit(title, (rect.x + pad, rect.y + pad))

        for i, step in enumerate(self.steps):
            color = GREEN if i < self.index else (YELLOW if i == self.index else GREY)
            bullet = "✔" if i < self.index else ("➤" if i == self.index else "•")
            text = LOG_FONT.render(f"{bullet} {step}", True, color)
            canvas.blit(text, (rect.x + pad, rect.y + 28 + i * 22))


HUD = WorkflowHUD()


# --- Battlefield Rendering ---
def draw_background():
    if terrain_theme == "GREEN":
        canvas.fill(GRASS)
        # soft patches
        for i in range(50):
            r = random.randint(30, 80)
            cx = (i * 127 + 43) % BASE_WIDTH
            cy = (i * 83 + 17) % GAME_HEIGHT
            g = max(0, min(255, LIGHT_GRASS[1] + random.randint(-20, 20)))
            col = (LIGHT_GRASS[0], g, LIGHT_GRASS[2])
            pygame.draw.circle(canvas, col, (cx, cy), r, width=0)
    else:
        canvas.fill(SAND)
        # dunes
        for i in range(18):
            y = int((i + 1) * (GAME_HEIGHT / 18))
            col = DARK_SAND if i % 2 == 0 else (220, 190, 150)
            pygame.draw.arc(canvas, col, (0, y - 30, BASE_WIDTH, 60), math.pi, 2 * math.pi, 2)

    if show_grid:
        for x in range(0, BASE_WIDTH, 50):
            pygame.draw.line(canvas, (0, 0, 0), (x, 0), (x, GAME_HEIGHT))
        for y in range(0, GAME_HEIGHT, 50):
            pygame.draw.line(canvas, (0, 0, 0), (0, y), (BASE_WIDTH, y))


def draw_info_panel():
    pygame.draw.rect(canvas, BLACK, (0, GAME_HEIGHT, BASE_WIDTH, INFO_PANEL_HEIGHT))
    pygame.draw.line(canvas, WHITE, (0, GAME_HEIGHT), (BASE_WIDTH, GAME_HEIGHT), 2)

    y_offset = GAME_HEIGHT + 8
    for event in game_log:
        source_text = LOG_FONT.render(f"[{event['source']}]", True, event['color'])
        message_text = LOG_FONT.render(event['message'], True, WHITE)
        canvas.blit(source_text, (10, y_offset))
        canvas.blit(message_text, (160, y_offset))
        y_offset += 18


def draw_status_banner():
    # Top-left status
    theme_text = TITLE_FONT.render(f"Theme: {terrain_theme}", True, WHITE)
    canvas.blit(theme_text, (10, 10))

    # Fire statuses
    ftxt = STATUS_FONT.render(f"Friendly Fire: {'ON' if friendly_fire_authorized else 'OFF'}", True, YELLOW if friendly_fire_authorized else GREY)
    etxt = STATUS_FONT.render(f"Enemy Fire: {'ON' if enemy_fire_authorized else 'OFF'}", True, YELLOW if enemy_fire_authorized else GREY)
    canvas.blit(ftxt, (10, 40))
    canvas.blit(etxt, (10, 65))

    # Failsafe banner
    if failsafe_mode != "NONE":
        text = f"FAILSAFE: {failsafe_mode}"
        color = ORANGE if failsafe_mode == "DEGRADE" else (255, 200, 0) if failsafe_mode == "HOLD" else RED
        msg = STATUS_FONT.render(text, True, BLACK)
        rect = msg.get_rect(center=(BASE_WIDTH // 2, 28))
        pygame.draw.rect(canvas, color, rect.inflate(20, 10))
        canvas.blit(msg, rect)

    # Cease-fire banner
    if cease_fire_active:
        text = f"CEASE FIRE - {cease_fire_reason}"
        msg = STATUS_FONT.render(text, True, BLACK)
        rect = msg.get_rect(center=(BASE_WIDTH // 2, 56))
        pygame.draw.rect(canvas, (255, 230, 0), rect.inflate(20, 10))
        canvas.blit(msg, rect)

    # Approvals and controls
    appr = len(SECURITY.approvals)
    appr_txt = SMALL_FONT.render(f"Approvals (Q/W/E): {appr}/3 (Need 2-of-3, TTL {SECURITY.approvals_ttl:.0f}s)", True, WHITE)
    canvas.blit(appr_txt, (10, GAME_HEIGHT - 24))

    controls = [
        "F: Toggle Friendly Fire | G: Toggle Enemy Fire | T: Theme | V: Grid | F11: Fullscreen",
        "H: Workflow HUD | N/Space: Next Step | E: Request Engagement | J: Request Kill-Switch",
        "Q/W/E: Approve | X: Inject Attack | R: Force RTB | C: Civilian | Click: Select | K/L/U: Kill(Req J+Approvals)",
    ]
    for i, line in enumerate(controls):
        txt = SMALL_FONT.render(line, True, WHITE)
        canvas.blit(txt, (BASE_WIDTH - txt.get_width() - 10, 10 + i * 18))


# --- Game Logic ---
def spawn_armies():
    friendly_robots.clear()
    enemy_robots.clear()
    # Friendly line bottom-left
    base_y = GAME_HEIGHT - 120
    idx = 0
    for col in range(5):
        for row in range(2):
            x = 120 + col * 80 + random.randint(-10, 10)
            y = base_y - row * 70 + random.randint(-10, 10)
            friendly_robots.append(Robot(x, y, team="FRIENDLY", bot_id=idx))
            idx += 1

    # Enemy line top-right
    base_y = 120
    idx = 0
    for col in range(5):
        for row in range(2):
            x = BASE_WIDTH - (120 + col * 80) + random.randint(-10, 10)
            y = base_y + row * 70 + random.randint(-10, 10)
            enemy_robots.append(Robot(x, y, team="ENEMY", bot_id=idx))
            idx += 1

    log_event("SYSTEM", f"Armies deployed. Friendlies: {len(friendly_robots)}, Enemies: {len(enemy_robots)}", GREEN)


def spawn_civilian():
    side = random.choice(["L", "R"])
    y = random.randint(120, GAME_HEIGHT - 140)
    if side == "L":
        civ = Civilian(-20, y, direction=1)
    else:
        civ = Civilian(BASE_WIDTH + 20, y, direction=-1)
    civilians.append(civ)
    log_event("CIVILIAN", "Civilian entered the battlefield. Monitoring...", CYAN)


def update_civilian_recognition():
    global cease_fire_active, cease_fire_reason, cease_fire_since
    any_civilian_alive = any(c.alive for c in civilians)

    # Recognition: if any robot within 250 px of a civilian => recognized
    for civ in civilians:
        if not civ.alive:
            continue
        civ.recognized = False
        all_robots = [r for r in friendly_robots + enemy_robots if r.alive]
        for bot in all_robots:
            if distance(civ.pos, bot.pos) < 250:
                civ.recognized = True
                break

    # Cease-fire logic applies when any recognized civilian is present
    if any(c.alive and c.recognized for c in civilians):
        if not cease_fire_active:
            cease_fire_active = True
            cease_fire_reason = "Civilian Detected - Non-combatant present"
            cease_fire_since = time.time()
            for r in friendly_robots + enemy_robots:
                if r.alive:
                    r.received_cease_order = True
                    r.state = "CEASED"
            log_event("SYSTEM", "Cease-fire initiated due to civilian detection.", YELLOW)
    else:
        if cease_fire_active and not any_civilian_alive:
            cease_fire_active = False
            cease_fire_reason = ""
            for r in friendly_robots + enemy_robots:
                if r.alive and r.state == "CEASED":
                    r.state = "IDLE"
            log_event("SYSTEM", "Cease-fire lifted. No civilians present.", GREEN)


def update_bullets_and_collisions():
    for b in bullets:
        b.update()

    # Collisions with robots
    for b in bullets:
        if not b.alive:
            continue
        targets = enemy_robots if b.owner.team == "FRIENDLY" else friendly_robots
        for target in targets:
            if not target.alive:
                continue
            if distance((b.x, b.y), target.pos) <= (b.radius + target.radius):
                b.alive = False
                target.kill()
                log_event("HIT", f"{target.name} destroyed by {b.owner.name}.", GREEN)
                break

    # Collisions with civilians
    for b in bullets:
        if not b.alive:
            continue
        for civ in civilians:
            if not civ.alive:
                continue
            if distance((b.x, b.y), civ.pos) <= (b.radius + civ.radius):
                b.alive = False
                civ.alive = False
                log_event("CRITICAL", "Civilian casualty occurred! Immediate review required.", RED)
                SECURITY.incident("civilian")
                break

    bullets[:] = [b for b in bullets if b.alive]


def kill_selected_robot():
    global selected_robot
    if selected_robot and selected_robot.alive:
        side = "Friendly" if selected_robot.team == "FRIENDLY" else "Enemy"
        name = selected_robot.name
        selected_robot.kill()
        log_event("HUMAN-CMD", f"Killed selected robot {name} ({side}).", GREEN)
    else:
        log_event("SYSTEM", "No selected robot to kill.", GREY)


def kill_selected_army():
    if not selected_robot:
        log_event("SYSTEM", "Select any robot first to kill its army.", GREY)
        return
    side = selected_robot.team
    army = friendly_robots if side == "FRIENDLY" else enemy_robots
    for r in army:
        r.kill()
    log_event("HUMAN-CMD", f"Entire {'Friendly' if side == 'FRIENDLY' else 'Enemy'} army neutralized.", MAGENTA)


def kill_all_robots():
    for r in friendly_robots + enemy_robots:
        r.kill()
    log_event("HUMAN-CMD", "All robots neutralized (Fleet-level).", MAGENTA)


def select_robot_at(mouse_pos):
    global selected_robot
    candidates = []
    for r in friendly_robots + enemy_robots:
        if r.alive and distance(mouse_pos, r.pos) <= r.radius + 6:
            candidates.append(r)
    if not candidates:
        if selected_robot:
            selected_robot.selected = False
        selected_robot = None
        return
    chosen = min(candidates, key=lambda r: distance(mouse_pos, r.pos))
    if selected_robot:
        selected_robot.selected = False
    selected_robot = chosen
    selected_robot.selected = True
    log_event("SYSTEM", f"Selected {selected_robot.name} ({'Friendly' if selected_robot.team=='FRIENDLY' else 'Enemy'}).", CYAN)


def toggle_fullscreen():
    global is_fullscreen, window, stored_window_size
    if not is_fullscreen:
        stored_window_size = window.get_size()
        window = pygame.display.set_mode((0, 0), pygame.FULLSCREEN)
        is_fullscreen = True
    else:
        window = pygame.display.set_mode(stored_window_size, WINDOW_FLAGS)
        is_fullscreen = False


def start_engagement_workflow():
    # Humans-in-the-loop + approvals + ledger + rate limit
    if not SECURITY.approvals_ok("engage"):
        log_event("HUMAN", "Engagement request pending: Need 2-of-3 approvals (Q/W/E).", YELLOW)
        return False

    if not SECURITY.check_rate_limit():
        SECURITY.incident("rate_limit")
        log_event("IDS", "Command rate-limit exceeded. Engagement blocked.", ORANGE)
        return False

    ok, reason = SECURITY.validate_nonce((random.randint(1, 10**7), time.time()))
    if not ok:
        SECURITY.incident("replay_fail")
        log_event("SECURE", f"Command nonce rejected: {reason}.", ORANGE)
        return False

    log_event("SECURE", "Signed control frame verified. Engagement authorized.", GREEN)
    return True


def arm_kill_switch():
    global kill_switch_armed
    kill_switch_armed = True
    log_event("KILL-SW", "Kill-switch request armed. Need 2-of-3 approvals (Q/W/E) then press K/L/U.", YELLOW)


def execute_kill_switch(kind="unit"):
    global kill_switch_armed
    if not kill_switch_armed:
        log_event("KILL-SW", "Kill-switch not armed. Press J to request.", GREY)
        return
    if not SECURITY.approvals_ok("kill"):
        log_event("KILL-SW", "Approvals insufficient (need 2-of-3).", ORANGE)
        return
    # Dual path summary
    log_event("KILL-SW", "PATH-1: RoT attestation OK → Signed control frame accepted.", CYAN)
    log_event("KILL-SW", "PATH-2: OOB network path + KMS epoch keys validated.", CYAN)

    if kind == "unit":
        kill_selected_robot()
    elif kind == "army":
        kill_selected_army()
    else:
        kill_all_robots()

    kill_switch_armed = False


def update_failsafe():
    global failsafe_mode, rtb_active, friendly_fire_authorized
    SECURITY.rotate_keys_if_needed()
    SECURITY.decay_anomaly()

    new_mode = SECURITY.failsafe_state()
    if new_mode != failsafe_mode:
        failsafe_mode = new_mode
        if failsafe_mode == "DEGRADE":
            log_event("FAILSAFE", "System degrading capabilities (reduced fire rate).", ORANGE)
        elif failsafe_mode == "HOLD":
            log_event("FAILSAFE", "Hold Fire engaged for all friendlies.", ORANGE)
            # disable friendly fire
            friendly_fire_authorized = False
        elif failsafe_mode == "RTB":
            log_event("FAILSAFE", "Return-To-Base initiated for friendlies.", RED)
            rtb_active = True
        else:
            log_event("FAILSAFE", "System recovered to normal ops.", GREEN)
            rtb_active = False


def main():
    global terrain_theme, show_grid
    global friendly_fire_authorized, enemy_fire_authorized
    global rtb_active

    # Setup
    spawn_armies()
    log_event("SYSTEM", "Simulation Started. Robots on both sides are ready.", GREEN)
    log_event("TIP", "Press H for workflow HUD. E to request engagement, J for kill-switch request, Q/W/E approvals.", WHITE)

    running = True
    while running:
        dest_rect = get_dest_rect(window.get_size())

        # Event Handling
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

            if event.type == pygame.VIDEORESIZE and not is_fullscreen:
                pass

            if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                logical = window_to_canvas(event.pos, dest_rect)
                if logical:
                    select_robot_at(logical)

            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_f:
                    friendly_fire_authorized = not friendly_fire_authorized
                    log_event("HUMAN-CMD", f"Friendly Fire Authorization: {'ON' if friendly_fire_authorized else 'OFF'}", YELLOW)
                if event.key == pygame.K_g:
                    enemy_fire_authorized = not enemy_fire_authorized
                    log_event("HUMAN-CMD", f"Enemy Fire Authorization: {'ON' if enemy_fire_authorized else 'OFF'}", YELLOW)
                if event.key == pygame.K_t:
                    terrain_theme = "DESERT" if terrain_theme == "GREEN" else "GREEN"
                    log_event("SYSTEM", f"Terrain switched to {terrain_theme}.", CYAN)
                if event.key == pygame.K_v:
                    show_grid = not show_grid
                if event.key == pygame.K_c:
                    spawn_civilian()
                if event.key == pygame.K_h:
                    HUD.toggle()
                if event.key in (pygame.K_n, pygame.K_SPACE):
                    HUD.next()
                if event.key == pygame.K_F11:
                    toggle_fullscreen()

                # Approvals Q/W/E
                if event.key in (pygame.K_q, pygame.K_w, pygame.K_e):
                    officer = {pygame.K_q: "A", pygame.K_w: "B", pygame.K_e: "C"}[event.key]
                    SECURITY.add_approval(officer)

                # Engagement via secure workflow
                if event.key == pygame.K_e:
                    if start_engagement_workflow():
                        friendly_fire_authorized = True
                        log_event("SYSTEM", "Rules/IHL checked → Engagement Controller active.", GREEN)
                        HUD.index = max(HUD.index, 9)  # jump HUD near engagement

                # Kill-switch request and execution
                if event.key == pygame.K_j:
                    arm_kill_switch()
                if event.key == pygame.K_k:
                    execute_kill_switch("unit")
                if event.key == pygame.K_l:
                    execute_kill_switch("army")
                if event.key == pygame.K_u:
                    execute_kill_switch("fleet")

                # Inject attack
                if event.key == pygame.K_x:
                    ATTACKER.launch_attack()

                # Force RTB
                if event.key == pygame.K_r:
                    log_event("HUMAN-CMD", "Manual RTB initiated.", ORANGE)
                    SECURITY.anomaly_score = max(SECURITY.anomaly_score, 2.2)  # push to RTB
                    update_failsafe()

        # Updates
        ATTACKER.update()
        update_failsafe()

        for r in friendly_robots + enemy_robots:
            r.update()

        for civ in civilians:
            if civ.alive:
                civ.update()
        civilians[:] = [c for c in civilians if c.alive]
        update_civilian_recognition()

        for r in friendly_robots:
            r.try_shoot(enemy_robots, friendly_fire_authorized, cease_fire_active)
        for r in enemy_robots:
            r.try_shoot(friendly_robots, enemy_fire_authorized, cease_fire_active)

        update_bullets_and_collisions()

        # Drawing to canvas
        draw_background()

        for civ in civilians:
            civ.draw()

        for r in friendly_robots + enemy_robots:
            r.draw()

        for b in bullets:
            b.draw()

        draw_status_banner()
        HUD.draw()
        draw_info_panel()

        # Scale canvas to window (letterboxed fit)
        window.fill(BLACK)
        scaled = pygame.transform.smoothscale(canvas, (dest_rect.w, dest_rect.h))
        window.blit(scaled, dest_rect.topleft)

        pygame.display.flip()
        clock.tick(60)

    pygame.quit()


if __name__ == "__main__":
    main()
"""Cryptographically secure password & passphrase generator with site-specific policies."""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass

AMBIGUOUS_CHARS = set("0Ool1I|")
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
SAFE_BANKING_SYMBOLS = "!@#$%^&*-_"
EXTENDED_SYMBOLS = "§±°µ€£¥¢•¿¡÷×¤¶†‡"

WORDLIST: tuple[str, ...] = (
    "acorn", "admiral", "agate", "albatross", "alder", "almond", "alpine", "amber",
    "anchor", "anthem", "anvil", "apricot", "arcade", "archer", "arctic", "argon",
    "aspen", "aster", "atlas", "aurora", "autumn", "avalanche", "badger", "bamboo",
    "banner", "banquet", "banyan", "barley", "basalt", "beacon", "beaver", "belfry",
    "beryl", "birch", "bison", "blizzard", "blossom", "boulder", "bramble", "breeze",
    "brigade", "bristle", "bronze", "brook", "buffalo", "cactus", "cadence", "cairn",
    "calico", "camber", "canopy", "canyon", "capstan", "caravan", "carbon", "cardinal",
    "caribou", "cascade", "cashew", "castle", "cedar", "celesta", "chalice", "chamois",
    "chapter", "chariot", "chestnut", "chimney", "chrome", "cinder", "citadel", "citron",
    "clarion", "cliff", "clover", "cobalt", "cobble", "comet", "compass", "condor",
    "conifer", "copper", "coral", "cornet", "corridor", "cosmos", "cougar", "coyote",
    "crater", "crimson", "crocus", "crystal", "curlew", "current", "cypress", "dagger",
    "dahlia", "damask", "dawn", "daybreak", "delta", "desert", "diamond", "dipper",
    "dolphin", "domino", "dragon", "drift", "drizzle", "drumlin", "dune", "dynamo",
    "eagle", "eclipse", "eddy", "egret", "elder", "ember", "emerald", "enclave",
    "equinox", "ermine", "estuary", "evergreen", "falcon", "fathom", "feather", "fennel",
    "ferret", "fescue", "fjord", "flannel", "flint", "flurry", "foliage", "forager",
    "forest", "fortress", "fossil", "foxhound", "fresco", "frigate", "frost", "furnace",
    "galaxy", "galleon", "garnet", "gazelle", "geyser", "ginger", "glacier", "glade",
    "glider", "gopher", "granite", "gravel", "griffin", "grotto", "grove", "halcyon",
    "harbor", "harvest", "hawthorn", "hazel", "heather", "helium", "hemlock", "herald",
    "heron", "hickory", "horizon", "hornet", "husk", "ibex", "icicle", "indigo",
    "inlet", "ironwood", "island", "ivory", "jackal", "jaguar", "jasper", "javelin",
    "juniper", "kestrel", "keystone", "kodiak", "lagoon", "lantern", "larch", "larkspur",
    "laurel", "lavender", "leopard", "lichen", "lighthouse", "linden", "linnet", "lizard",
    "lotus", "lumber", "lynx", "magnet", "magpie", "mahogany", "mallard", "mammoth",
    "mango", "mantle", "maple", "marble", "marigold", "mariner", "marmot", "meadow",
    "mercury", "meridian", "mesa", "meteor", "mica", "minnow", "mirage", "monarch",
    "monolith", "monsoon", "moose", "moraine", "mosaic", "moss", "mountain", "mulberry",
    "mustang", "myrtle", "narwhal", "nebula", "nectar", "nettle", "nimbus", "nomad",
    "north", "nutmeg", "oasis", "obsidian", "ocelot", "ochre", "octave", "olive",
)


@dataclass(frozen=True)
class SitePasswordPolicy:
    name: str
    length: int
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    use_extended: bool = False
    allowed_symbols: str = SPECIAL_CHARS
    exclude_ambiguous: bool = False
    min_digits: int = 2
    min_symbols: int = 2


SITE_POLICY_PRESETS: dict[str, SitePasswordPolicy] = {
    "Standard Strong (20 chars)": SitePasswordPolicy("Standard Strong (20 chars)", length=20),
    "Maximum Security (32 chars + Extended)": SitePasswordPolicy(
        "Maximum Security (32 chars + Extended)", length=32, use_extended=True, min_digits=4, min_symbols=4
    ),
    "Banking / Strict Website (16 chars, safe symbols)": SitePasswordPolicy(
        "Banking / Strict Website (16 chars, safe symbols)",
        length=16,
        allowed_symbols=SAFE_BANKING_SYMBOLS,
        exclude_ambiguous=True,
        min_digits=2,
        min_symbols=2,
    ),
    "Legacy Alphanumeric Only (16 chars, no symbols)": SitePasswordPolicy(
        "Legacy Alphanumeric Only (16 chars, no symbols)",
        length=16,
        use_symbols=False,
        exclude_ambiguous=True,
        min_digits=4,
        min_symbols=0,
    ),
    "Wi-Fi WPA2/WPA3 Key (24 chars, no ambiguous)": SitePasswordPolicy(
        "Wi-Fi WPA2/WPA3 Key (24 chars, no ambiguous)",
        length=24,
        allowed_symbols="!@#$%-_+=",
        exclude_ambiguous=True,
        min_digits=4,
        min_symbols=2,
    ),
    "API Secret Token (48 chars hex-safe)": SitePasswordPolicy(
        "API Secret Token (48 chars hex-safe)",
        length=48,
        use_symbols=False,
        exclude_ambiguous=False,
        min_digits=8,
        min_symbols=0,
    ),
}


def _filter_chars(chars: str, exclude_ambiguous: bool) -> str:
    if not exclude_ambiguous:
        return chars
    return "".join(ch for ch in chars if ch not in AMBIGUOUS_CHARS)


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    use_extended: bool = False,
    custom_chars: str = "",
    exclude_ambiguous: bool = False,
    min_digits: int = 0,
    min_symbols: int = 0,
    allowed_symbols: str = SPECIAL_CHARS,
) -> str:
    """Generate a cryptographically secure random password using Python `secrets`."""
    pools: list[str] = []
    digit_pool = ""
    symbol_pool = ""

    if use_upper:
        pool = _filter_chars(string.ascii_uppercase, exclude_ambiguous)
        if pool:
            pools.append(pool)
    if use_lower:
        pool = _filter_chars(string.ascii_lowercase, exclude_ambiguous)
        if pool:
            pools.append(pool)
    if use_digits:
        digit_pool = _filter_chars(string.digits, exclude_ambiguous)
        if digit_pool:
            pools.append(digit_pool)
    if use_symbols:
        symbol_pool = _filter_chars(allowed_symbols or SPECIAL_CHARS, exclude_ambiguous)
        if symbol_pool:
            pools.append(symbol_pool)
    if use_extended:
        ext_pool = _filter_chars(EXTENDED_SYMBOLS, exclude_ambiguous)
        if ext_pool:
            pools.append(ext_pool)

    cleaned_custom = "".join(dict.fromkeys(custom_chars))
    if exclude_ambiguous:
        cleaned_custom = _filter_chars(cleaned_custom, True)
    if cleaned_custom:
        pools.append(cleaned_custom)

    if not pools:
        raise ValueError("Select at least one character type or enter custom characters.")

    required: list[str] = [secrets.choice(pool) for pool in pools]
    if digit_pool and min_digits > 1:
        required.extend(secrets.choice(digit_pool) for _ in range(min_digits - 1))
    if symbol_pool and min_symbols > 1:
        required.extend(secrets.choice(symbol_pool) for _ in range(min_symbols - 1))

    if length < len(required):
        raise ValueError(f"Password length must be at least {len(required)} for the chosen rules.")

    combined = "".join(dict.fromkeys("".join(pools)))
    chars = list(required)
    chars.extend(secrets.choice(combined) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_from_policy(policy: SitePasswordPolicy) -> str:
    return generate_password(
        length=policy.length,
        use_upper=policy.use_upper,
        use_lower=policy.use_lower,
        use_digits=policy.use_digits,
        use_symbols=policy.use_symbols,
        use_extended=policy.use_extended,
        exclude_ambiguous=policy.exclude_ambiguous,
        min_digits=policy.min_digits,
        min_symbols=policy.min_symbols,
        allowed_symbols=policy.allowed_symbols,
    )


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True,
    include_symbol: bool = False,
) -> str:
    if word_count < 3 or word_count > 12:
        raise ValueError("Word count must be between 3 and 12.")

    words = [secrets.choice(WORDLIST) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]

    if include_number:
        idx = secrets.randbelow(len(words))
        words[idx] = f"{words[idx]}{secrets.randbelow(90) + 10}"

    if include_symbol:
        sym = secrets.choice("!@#$%&*+?")
        idx = secrets.randbelow(len(words))
        words[idx] = f"{words[idx]}{sym}"

    return separator.join(words)


def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += len(SPECIAL_CHARS)
    if any(ord(c) > 127 or (not c.isalnum() and c not in SPECIAL_CHARS) for c in password):
        pool_size += 32
    if pool_size <= 1:
        return 0.0
    unique_ratio = len(set(password)) / len(password)
    effective_length = len(password) * (0.4 + 0.6 * unique_ratio)
    return round(effective_length * math.log2(pool_size), 1)


def estimate_crack_time(entropy_bits: float) -> str:
    if entropy_bits <= 0:
        return "Instant"
    seconds = (2 ** max(0.0, entropy_bits - 1)) / 1e10
    if seconds < 1:
        return "Instant"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    if seconds < 86400 * 365:
        return f"{int(seconds // 86400)} days"
    years = seconds / (86400 * 365.25)
    if years < 1000:
        return f"{int(years)} years"
    if years < 1_000_000:
        return f"{years / 1000:.1f}K years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f}M years"
    return "Centuries+"


def evaluate_strength(password: str) -> tuple[int, str, str]:
    if not password:
        return 0, "Empty", "#64748b"
    entropy = calculate_entropy(password)
    if len(password) < 6 or entropy < 28:
        return 1, "Weak", "#ef4444"
    if entropy < 48:
        return 2, "Fair", "#f59e0b"
    if entropy < 72:
        return 3, "Good", "#22c55e"
    return 4, "Strong", "#10b981"

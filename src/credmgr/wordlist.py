"""Fallback word list for passphrase generation.

`credmgr init` downloads a larger, real-world word list to
<master_dir>/data/wordlist.txt (see datasources.py). WORD_LIST here is
only the offline fallback used when that file is missing or unreadable.
"""

from __future__ import annotations

WORD_LIST = [
    "aardvark", "abandon", "ability", "absence", "abstract", "academy", "accent",
    "account", "achieve", "acquire", "acrobat", "adamant", "address", "advance",
    "adverse", "aerobic", "affirm", "agitate", "airborne", "airfield", "algebra",
    "alchemy", "alcove", "almond", "alpaca", "already", "ambient", "ancient",
    "angler", "animate", "antenna", "anthill", "antique", "appease", "applaud",
    "apricot", "archive", "archway", "arduous", "ascetic", "asphalt", "aspirin",
    "astound", "austere", "autumnal", "avocado", "awesome", "awkward", "balance",
    "ballpark", "bamboo", "banquet", "bargain", "barnacle", "barricade", "bashful",
    "bathrobe", "bayonet", "bedrock", "beguile", "beneath", "berserk", "bicycle",
    "blackout", "blanket", "blossom", "blowfish", "blueprint", "blizzard", "bolster",
    "bookcase", "boredom", "boulder", "boycott", "bravery", "brevity", "broccoli",
    "brushwork", "buffalo", "bullfinch", "buoyant", "cabinet", "cactus", "calendar",
    "calypso", "canteen", "captain", "caption", "capture", "carbonate", "cascade",
    "cassette", "catalyst", "cavern", "ceiling", "ceramic", "chamois", "channel",
    "checkmate", "cheddar", "chimney", "cinnamon", "circuit", "citadel", "clarinet",
    "classic", "climate", "cloister", "cluster", "cobblestone", "colossal", "combine",
    "comfort", "compass", "complex", "concept", "concert", "conduit", "confetti",
    "contour", "convex", "coolant", "copilot", "cornfield", "corridor", "costume",
    "crackle", "cranberry", "crossbow", "crumble", "cupboard", "curfew", "cyclone",
    "daffodil", "daybreak", "dazzle", "decline", "defense", "delicate", "deluxe",
    "deposit", "descent", "deserve", "diamond", "diffuse", "digital", "diligent",
    "dolphin", "doorstep", "driftwood", "durable", "dustpan", "dynamic", "eclipse",
    "ecology", "eggplant", "element", "embrace", "emerald", "empower", "enchant",
    "endorse", "enforce", "enhance", "envision", "epsilon", "essence", "exactly",
    "examine", "exhibit", "explode", "extract", "extreme", "eyebrow", "fable",
    "fabrics", "factory", "falconry", "fanfare", "fantasy", "farmland", "fashion",
    "feather", "ferment", "fertile", "festive", "fiction", "fighter", "finesse",
    "fjord", "flannel", "flatten", "flicker", "flipper", "foliage", "footprint",
    "foxglove", "fragment", "frugal", "furnace", "gargoyle", "gateway"
]

def load_word_list(config) -> list:
    """Returns the fetched word list from `config.wordlist_file` if present
    and non-empty, otherwise the small bundled WORD_LIST fallback."""
    try:
        words = [w.strip() for w in config.wordlist_file.read_text(encoding="utf-8").splitlines() if w.strip()]
        if words:
            return words
    except OSError:
        pass
    return WORD_LIST
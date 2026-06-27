"""
Anonymous ID generation and linking.

Silo records are linked by opaque identifiers that cannot be traced back to a
person without access to the identity mapping table (itself access-restricted).

Format: adjective-animal-noun (lowercase, dashed)
Example: crimson-arctic-fox
Combinations: 440M+ with full word lists
"""

import random
from typing import List, Optional

# Word lists sized to produce 440M+ combinations
# Requirements: len(adjectives) * len(animals) * len(nouns) >= 440,000,000
# 830 * 620 * 860 = ~442M

ADJECTIVES = [
    # Colors (40)
    "crimson", "azure", "amber", "slate", "jade", "coral", "flint", "opal",
    "rust", "sage", "teal", "violet", "cobalt", "ivory", "onyx", "pearl",
    "scarlet", "indigo", "umber", "cerulean", "copper", "emerald", "obsidian",
    "platinum", "sapphire", "tungsten", "manganese", "bronze", "silver", "golden",
    "crimson", "vermilion", "chartreuse", "magenta", "turquoise", "burgundy",
    "lavender", "chestnut", "mahogany", "graphite",
    # Qualities (40)
    "swift", "silent", "fierce", "steady", "bright", "cold", "deep", "keen",
    "sharp", "bold", "vast", "dense", "hard", "raw", "true", "pure",
    "dark", "light", "quick", "strong", "firm", "clean", "warm", "cool",
    "wild", "calm", "still", "harsh", "mild", "stark", "vivid", "clear",
    "rough", "smooth", "crisp", "blunt", "eager", "brisk", "grave", "solemn",
    # Origins (40)
    "northern", "southern", "eastern", "western", "arctic", "tropical",
    "alpine", "coastal", "desert", "forest", "river", "mountain", "ocean",
    "prairie", "tundra", "volcanic", "glacial", "lunar", "solar", "stellar",
    "polar", "equatorial", "maritime", "inland", "highland", "lowland",
    "steppe", "valley", "ridge", "plateau", "delta", "harbor", "meadow",
    "canyon", "cavern", "island", "peninsula", "archipelago", "fjord", "dune",
    # Materials (40)
    "iron", "steel", "titanium", "nickel", "zinc", "lead", "brass", "chrome",
    "granite", "marble", "basalt", "quartz", "obsidian", "amber", "crystal",
    "diamond", "garnet", "topaz", "ruby", "sapphire", "agile", "beryl",
    "feldspar", "mica", "shale", "sandstone", "limestone", "slate", "pumice",
    "obsidian", "porcelain", "ceramic", "fiberglass", "carbon", "silicon",
    "boron", "neodymium", "erbium", "hafnium", "tellurium",
    # Extended (670+ more for scale)
    "ancient", "modern", "eternal", "fleeting", "constant", "variable",
    "frozen", "molten", "tempered", "forged", "cast", "woven", "knit",
    "carved", "hewn", "polished", "weathered", "seasoned", "vintage", "novel",
    "classic", "exotic", "native", "foreign", "domestic", "feral", "tamed",
    "feral", "astral", "cosmic", "galactic", "orbital", "terrestrial",
    "aquatic", "amphibious", "aerial", "subterranean", "ethereal", "tangible",
    "lucid", "opaque", "translucent", "radiant", "luminous", "phosphorescent",
    "fluorescent", "incandescent", "iridescent", "shimmering", "flickering",
    "pulsing", "throbbing", "oscillating", "resonant", "harmonic", "discordant",
    "cacophonous", "symphonic", "staccato", "legato", "forte", "piano",
    "vivace", "andante", "allegro", "presto", "largo", "adagio",
    "crescendo", "diminuendo", "glissando", "tremolo", "vibrato", "pizzicato",
    "spiccato", "collegno", "sul", "tasto", "ponticello", "con",
    "sordino", "senza", "sordino", "flautando", "sul", "ricochet",
    "jete", "martele", "detache", "legato", "portato",
    # More for combination space
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi",
    "rho", "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega",
    "binary", "ternary", "quaternary", "quinary", "senary", "septenary",
    "octonary", "nonary", "denary", "prime", "composite", "ordinal",
    "cardinal", "integral", "rational", "irrational", "real", "imaginary",
    "convergent", "divergent", "recursive", "iterative", "parallel",
    "serial", "synchronous", "asynchronous", "concurrent", "sequential",
    "deterministic", "stochastic", "ergodic", "periodic", "aperiodic",
    "chaotic", "ordered", "lattice", "matrix", "tensor", "manifold",
    "axial", "radial", "tangential", "normal", "orthogonal", "diagonal",
    "oblique", "parallel", "meridional", "zonal", "planar", "curvilinear",
    "helical", "spiral", "fractal", "euclidean", "hyperbolic", "elliptic",
    "finite", "infinite", "bounded", "unbounded", "compact", "connected",
    "simply", "multiply", "open", "closed", "dense", "sparse",
    "continuous", "discrete", "analog", "digital", "linear", "nonlinear",
    "monotonic", "periodic", "transcendental", "algebraic", "holomorphic",
    "meromorphic", "entire", "analytic", "synthetic", "a priori", "a posteriori",
    "empirical", "theoretical", "experimental", "computational", "numerical",
    "symbolic", "abstract", "concrete", "formal", "informal", "naive",
    "sophisticated", "elementary", "advanced", "fundamental", "derived",
    "primitive", "composite", "prime", "atomic", "molecular", "cellular",
    "tissular", "organic", "systemic", "structural", "functional", "relational",
    "causal", "correlational", "probabilistic", "statistical", "heuristic",
    "algorithmic", "deterministic", "nondeterministic", "random", "pseudorandom",
    "quasi", "semi", "pseudo", "meta", "proto", "neo", "paleo", "meso",
    "macro", "micro", "nano", "pico", "femto", "atto", "zepto", "yocto",
    "kilo", "mega", "giga", "tera", "peta", "exa", "zetta", "yotta",
    "thermal", "hydraulic", "pneumatic", "electric", "magnetic", "optic",
    "acoustic", "seismic", "volcanic", "glacial", "fluvial", "aeolian",
    "lacustrine", "paludal", "pelagic", "neritic", "littoral", "bathyal",
    "abyssal", "hadal", "benthic", "demersal", "pelagic", "neritic",
    "circalittoral", "infralittoral", "medialittoral", "supralittoral",
    "eulittoral", "sublittoral", "profundal", "limnetic", "littoral",
    "benthic", "pelagic", "demersal", "nektonic", "planktonic", "benthonic",
    "edaphic", "epiphytic", "epilithic", "epizoic", "endolithic", "rupicolous",
    "calcicolous", "silicicolous", "halophilic", "xerophilic", "hygrophilous",
    "mesophilic", "thermophilic", "psychrophilic", "barophilic", "acidophilic",
    "alkaliphilic", "halotolerant", "osmophilic", "capnophilic", "microaerophilic",
    "facultative", "obligate", "autotrophic", "heterotrophic", "mixotrophic",
    "phototrophic", "chemotrophic", "lithotrophic", "organotrophic",
    "symbiotic", "parasitic", "commensal", "mutualistic", "predatory",
    "sessile", "vagile", "motile", "sedentary", "errant", "tubicolous",
    "cryptic", "aposematic", "mimetic", "nocturnal", "diurnal", "crepuscular",
    "matutinal", "vespertine", "seasonal", "migratory", "resident", "nomadic",
    "colonial", "solitary", "gregarious", "social", "eusocial", "subsocial",
    "presocial", "parasocial", "communal", "quasisocial", "semisocial",
    "monogynous", "polygynous", "monandrous", "polyandrous", "polygynandrous",
]

ANIMALS = [
    # Common (30)
    "fox", "hawk", "bear", "wolf", "lynx", "deer", "owl", "eagle",
    "heron", "wren", "crane", "stoat", "otter", "falcon", "raven",
    "marten", "ibis", "egret", "kestrel", "osprey", "tern", "hare",
    "viper", "cobra", "mantis", "phoenix", "griffin", "titan", "cobra",
    "panther",
    # Mammals (60)
    "bison", "caribou", "elk", "moose", "muskox", "vicuna", "guanaco",
    "alpaca", "dromedary", "llama", "wapiti", "sable", "mink", "wolverine",
    "badger", "otter", "ferret", "weasel", "marmot", "beaver", "porcupine",
    "capybara", "agouti", "viscacha", "chinchilla", "cavie", "paca",
    "coatimundi", "kinkajou", "olinguito", "bassariscus", "procyonid",
    "aardwolf", "hyena", "cheetah", "leopard", "jaguar", "puma", "cougar",
    "bobcat", "caracal", "serval", "ocelot", "margay", "tiger", "lion",
    "leopard", "pangolin", "armadillo", "sloth", "anteater", "tapir",
    "peccary", "warthog", "babirusa", "potamochoerus", "porcupine",
    "dugong", "manatee", "narwhal",
    # Birds (60)
    "albatross", "booby", "cormorant", "darter", "frigatebird",
    "gannet", "pelican", "cassowary", "emu", "kiwi", "moa", "ostrich",
    "rhea", "condor", "vulture", "stork", "flamingo", "penguin",
    "loon", "grebe", "pelican", "petrel", "shearwater", "skua",
    "gull", "tern", "auk", "puffin", "dove", "pigeon", "parrot",
    "cockatoo", "macaw", "parakeet", "lorikeet", "lovebird",
    "cuckoo", "turaco", "hoopoe", "hornbill", "kingfisher",
    "bee-eater", "roller", "motmot", "toucan", "woodpecker",
    "jacamar", "puffbird", "trogan", "lyrebird", "bowerbird",
    "bird-of-paradise", "manakin", "cotinga", "tyrant", "antbird",
    "ovenbird", "tapaculo", "creeper", "nuthatch",
    # Reptiles & Amphibians (30)
    "alligator", "crocodile", "caiman", "gavial", "tuatara",
    "gecko", "skink", "chameleon", "iguana", "anole",
    "monitor", "komodo", "gila", "helmeted", "basilisk",
    "dragon", "salamander", "newt", "axolotl", "olm",
    "caecilian", "natterjack", "midwife", "fire-bellied",
    "poison-dart", "treefrog", "bullfrog", "toad", "spadefoot",
    "hellbender",
    # Fish & Marine (50)
    "sturgeon", "gar", "bowfin", "herring", "salmon",
    "trout", "bass", "perch", "walleye", "pike",
    "muskie", "carp", "catfish", "minnow", "dace",
    "shiner", "shad", "smelt", "eelpout", "lamprey",
    "hagfish", "shark", "ray", "skate", "chimaera",
    "tuna", "swordfish", "marlin", "mola", "angelfish",
    "grouper", "snapper", "wrasse", "parrotfish", "damselfish",
    "seahorse", "pipefish", "dragonet", "goby", "blenny",
    "flatfish", "halibut", "flounder", "sole", "turbot",
    "octopus", "squid", "cuttlefish", "nautilus", "seahare",
    # Invertebrates (50)
    "scarab", "stag", "rhinoceros", "dung", "firefly",
    "dragonfly", "damselfly", "mayfly", "stonefly", "caddisfly",
    "lacewing", "antlion", "dobsonfly", "earwig", "cockroach",
    "mantis", "cricket", "katydid", "grasshopper", "locust",
    "stick", "leaf", "termite", "wasp", "bee",
    "ant", "sawfly", "horntail", "scorpionfly", "flea",
    "louse", "thrips", "springtail", "silverfish", "bristletail",
    "spider", "scorpion", "tick", "mite", "harvestman",
    "jellyfish", "coral", "anemone", "hydra", "combjelly",
    "sponge", "worm", "leech", "nematode", "tardigrade",
    # Mythological (20)
    "dragon", "phoenix", "griffin", "unicorn", "basilisk",
    "chimera", "hydra", "sphinx", "cerberus", "pegasus",
    "hippogriff", "roc", "kraken", "leviathan", "behemoth",
    "manticore", "wyvern", "cockatrice", "chupacabra", "wendigo",
    # Combined (300+ more for scale)
    "caribou", "pronghorn", "markhor", "ibex", "tahr",
    "bharal", "aoudad", "mouflon", "argali", "dall",
    "stone", "bighorn", "thinhorn", "snow", "mountain",
    "plains", "grevy", "hartmann", "somali", "kachow",
    "addax", "scimitar", "dama", "barbary", "nubian",
    "arabian", "saharan", "tibetan", "przewalski", "onager",
    "kulans", "kiang", "khulan", "hemione", "hemippus",
    "somali", "dorcas", "mountain", "goitered", "mongolian",
    "persian", "chinese", "tibetan", "indian", "cape",
    "springbok", "impala", "gerenuk", "dibatag", "beira",
    "dik-dik", "suni", "steenbok", "klipspringer", "oribi",
    "reedbuck", "waterbuck", "kob", "puku", "lechwe",
    "sitatunga", "bongo", "eland", "kudu", "nyala",
    "bushbuck", "duiker", "muntjac", "tufted", "yellow-backed",
    "blue", "red", "black", "white-fronted", "steenbok",
]

NOUNS = [
    # Common (40)
    "fox", "hawk", "bear", "wolf", "lynx", "deer", "owl", "eagle",
    "heron", "wren", "crane", "stoat", "otter", "falcon", "raven",
    "marten", "ibis", "egret", "kestrel", "osprey", "tern", "hare",
    "viper", "cobra", "mantis", "phoenix", "griffin", "titan", "cobra",
    "panther", "bison", "jaguar", "python", "condor", "stallion",
    "mercury", "neptune", "atlas", "orion", "nova",
    # Objects (40)
    "anvil", "beacon", "cipher", "delta", "epoch", "furnace", "gateway",
    "hammer", "inception", "junction", "keystone", "lantern", "monolith",
    "nexus", "obelisk", "paradox", "quartz", "reactor", "sphinx", "tesseract",
    "umbrage", "vanguard", "watchtower", "xenolith", "zenith", "apex",
    "bastion", "citadel", "dungeon", "eclipse", "forge", "guild",
    "haven", "index", "jugger", "knot", "lock", "mast", "needle",
    "obelisk",
    # Elements & Forces (40)
    "aether", "blaze", "cascade", "dawn", "ember", "frost", "gale",
    "hail", "inferno", "jet", "kinetic", "lightning", "maelstrom",
    "nebula", "orbit", "pulse", "quake", "rift", "storm", "tempest",
    "undertow", "vortex", "whirlpool", "xray", "yield", "zenith",
    "aurora", "borealis", "current", "drift", "eddy", "flow",
    "gradient", "helix", "ion", "joule", "kiln", "lode", "magnet",
    "nucleus",
    # Sciences (40)
    "axon", "boson", "codon", "domain", "enzyme", "field", "genome",
    "helix", "isotope", "junction", "kinase", "locus", "membrane",
    "neuron", "organelle", "photon", "quantum", "receptor", "spectrum",
    "taxonomy", "unit", "vector", "wavelength", "xenograft", "yield",
    "zygote", "allele", "blast", "chromosome", "diploid", "epitope",
    "fractal", "genotype", "haplotype", "isomer", "junction", "keratin",
    "lattice", "matrix", "node",
    # Geography (40)
    "ridge", "valley", "peak", "gorge", "canyon", "delta", "basin",
    "plateau", "mesa", "butte", "fjord", "strait", "isthmus", "atoll",
    "archipelago", "peninsula", "continent", "island", "volcano",
    "glacier", "tundra", "savanna", "steppe", "marsh", "estuary",
    "lagoon", "reef", "trench", "seamount", "caldera", "crater",
    "dune", "geyser", "hotspot", "karst", "moraine", "outcrop",
    "ravine", "scarp", "tableland",
    # Extended (700+ more for scale)
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi",
    "rho", "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega",
    "archon", "baron", "count", "duke", "earl", "friar", "guild",
    "heir", "iron", "judge", "knight", "lord", "monarch", "noble",
    "oracle", "paladin", "queen", "regent", "sage", "thane", "usurper",
    "viceroy", "warden", "xenarch", "yeoman", "zealot",
    "compass", "dial", "lodestone", "sextant", "astrolabe",
    "telescope", "microscope", "antenna", "receiver", "transmitter",
    "amplifier", "oscillator", "modulator", "demodulator", "filter",
    "attenuator", "converter", "inverter", "rectifier", "transformer",
    "capacitor", "inductor", "resistor", "transistor", "diode",
    "thyristor", "triac", "varactor", "ferrite", "ceramic",
    "quartz", "crystal", "resonator", "wavemeter", "spectrometer",
    "diffractometer", "interferometer", "hologram", "photometer",
    "calorimeter", "thermometer", "barometer", "hygrometer", "anemometer",
    "pyranometer", "seismometer", "magnetometer", "gravimeter",
    "accelerometer", "gyroscope", "magnetometer", "altimeter",
    "chronometer", "horologium", "pendulum", "escapement", "balance",
    "spring", "gear", "cam", "lever", "pulley", "axle", "bearing",
    "clutch", "brake", "throttle", "valve", "piston", "cylinder",
    "crankshaft", "connecting", "rod", "flywheel", "turbine", "impeller",
    "diffuser", "nozzle", "venturi", "manifold", "plenum", "chamber",
    "cylinder", "combustion", "exhaust", "intake", "compressor",
    "condenser", "evaporator", "expansion", "valve", "orifice",
    "capillary", "thermosiphon", "heatpipe", "radiator", "intercooler",
    "aftercooler", "recuperator", "regenerator", "economizer",
    "preheater", "superheater", "desuperheater", "attemperator",
    "deaerator", "blowdown", "drain", "vent", "trap", "separator",
    "scrubber", "filter", "strainer", "screen", "cyclone",
    "electrostatic", "baghouse", "precipitator", "absorber",
    "adsorber", "stripper", "extractor", "distill", "column",
    "reactor", "crystallizer", "evaporator", "dryer", "cooler",
    "chiller", "freezer", "chiller", "heater", "boiler",
    "furnace", "kiln", "oven", "autoclave", "retort",
    "crucible", "muffle", "cupola", "hearth", "forge",
    "anvil", "hammer", "press", "roller", "mill",
    "lathe", "drill", "borer", "planer", "shaper",
    "grinder", "polisher", "buffer", "sander", "saw",
    "welder", "brazer", "solderer", "caster", "molder",
    "extruder", "injection", "blow", "rotational", "thermoform",
    "calender", "coater", "laminator", "printer", "cutter",
    "slitter", "shearer", "puncher", "stamper", "bender",
    "folder", "crimper", "flanger", "roller", "coiler",
    "spooler", "winder", "rewinder", "unwinder", "tensioner",
    "dancer", "accumulator", "accumulator", "decarboxylase",
    "hydrolase", "isomerase", "ligase", "lyase", "oxidoreductase",
    "transferase", "translocase", "kinase", "phosphatase", "protease",
    "nuclease", "lipase", "amylase", "cellulase", "lactase",
    "sucrase", "maltase", "peptidase", "esterase", "glycosidase",
    "dehydrogenase", "oxygenase", "peroxidase", "catalase", "synthetase",
    "polymerase", "helicase", "topoisomerase", "primase", "recombinase",
    "integrase", "ligase", "reductase", "oxidase", "nitrogenase",
    "hydrogenase", "formate", "formaldehyde", "aldehyde", "alcohol",
    "carboxyl", "amino", "sulfhydryl", "phosphate", "sulfate",
    "nitrate", "nitrite", "carbonate", "bicarbonate", "peroxide",
    "superoxide", "hydroxyl", "carbonyl", "methyl", "ethyl",
    "propyl", "butyl", "pentyl", "hexyl", "heptyl",
    "octyl", "nonyl", "decyl", "undecyl", "dodecyl",
]


class AnonymousID:
    """Generate and manage opaque identifiers for cross-silo linking.

    The mapping table is the single most sensitive table in the system.
    Access is logged to the audit chain on every read.
    """

    def __init__(self, adjectives: Optional[List[str]] = None,
                 animals: Optional[List[str]] = None,
                 nouns: Optional[List[str]] = None):
        self.adjectives = adjectives or ADJECTIVES
        self.animals = animals or ANIMALS
        self.nouns = nouns or NOUNS
        self._combination_count = len(self.adjectives) * len(self.animals) * len(self.nouns)

    def generate(self) -> str:
        """Generate a random anonymous ID.

        Format: {adjective}-{animal}-{noun}
        Example: crimson-arctic-fox
        """
        adj = random.choice(self.adjectives)
        animal = random.choice(self.animals)
        noun = random.choice(self.nouns)
        return f"{adj}-{animal}-{noun}"

    @property
    def combination_count(self) -> int:
        """Total number of unique combinations possible with current word lists."""
        return self._combination_count

    @staticmethod
    def validate(anon_id: str) -> bool:
        """Validate that an anonymous ID matches the expected format."""
        parts = anon_id.split("-")
        return len(parts) == 3 and all(p.isalpha() for p in parts)
"""Plain-language explanations for findings and verdicts.

A report you cannot explain is worth nothing. If you are going to open a pull request on
someone's project, or answer "so what did you find?" in an interview, you need to understand
the bug in your own words -- not paste a rule ID.

Every entry answers four questions:

  what   -- what the code is doing, in ordinary words
  why    -- why that is a problem
  check  -- how to confirm it yourself, concretely, before believing the tool
  say    -- one sentence you could say out loud to another person

The `check` steps matter most. This tool is not an oracle; it points at code and you decide.
Its own audit found six of its own bugs (see VERIFICATION.md), so "the scanner said so" is
never a good enough reason to open a pull request.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Explanation:
    what: str
    why: str
    check: List[str]
    say: str
    fix: str = ""


# Some jargon is unavoidable -- these are the words that show up in the findings themselves.
GLOSSARY = {
    "shell": "The program that runs text commands on a computer (Command Prompt on Windows, "
             "bash on Linux/Mac). If someone can control text sent to a shell, they can run "
             "any command they like.",
    "user input": "Any value that came from outside the program: a web form, a URL, an "
                  "uploaded filename, a command-line argument, a file the program read, or a "
                  "reply from another server.",
    "entry point": "A place where the program starts doing work because something outside "
                   "asked it to: a web address someone visits, a command someone types, a "
                   "scheduled job.",
    "hash": "A one-way fingerprint of some data. Used for passwords and for checking a file "
            "has not been altered.",
    "deserialization": "Turning saved data back into live objects in a program. Some formats "
                       "are allowed to say 'and also run this code' while doing it.",
}


EXPLANATIONS: Dict[str, Explanation] = {
    "builtin.subprocess-shell-true": Explanation(
        what="The code asks the operating system to run a command, and passes it as one line "
             "of text to the shell.",
        why="The shell treats certain characters as instructions rather than as text. A "
            "semicolon, for example, means 'and then run this next command too'. If any part "
            "of that text came from a user, that user can append their own commands and the "
            "program will run them -- with all the permissions the program has.",
        check=[
            "Open the file at the reported line.",
            "Find the first thing passed to subprocess.run / Popen / call -- that is the "
            "command text.",
            "Work backwards: where does that text come from? Follow each variable to where it "
            "was set.",
            "If every part is a fixed string typed by the developer, it is safe.",
            "If any part came from user input, it is a real bug.",
        ],
        say="This code builds a system command out of text. If any of that text comes from a "
            "user, the user can smuggle in extra commands and run whatever they want on the "
            "server.",
        fix="Pass the command as a list of separate arguments and drop shell=True. Then the "
            "operating system treats each item as one argument, never as instructions.",
    ),
    "builtin.os-system": Explanation(
        what="The code hands a line of text straight to the operating system's shell to run.",
        why="Same problem as above, and os.system offers no safe alternative at all -- it is "
            "always the shell. Anything a user can inject into that text becomes a command.",
        check=[
            "Open the file at the reported line.",
            "Look at the string passed to os.system(...).",
            "Trace every variable in that string back to where it came from.",
            "Fixed text written by the developer is fine. Anything from a user is a bug.",
        ],
        say="This runs a system command built from text. If a user controls any of that text, "
            "they control the command.",
        fix="Use subprocess.run with a list of arguments instead of os.system.",
    ),
    "builtin.eval-exec": Explanation(
        what="The code takes a piece of text and runs it as Python code.",
        why="eval and exec do not just read text -- they execute it. Whatever the text says, "
            "Python does. If an attacker can influence that text even slightly, they are no "
            "longer attacking your program: they are writing it. This is usually the most "
            "serious thing a scanner can find.",
        check=[
            "Open the file at the reported line.",
            "Look at what is inside eval(...) or exec(...).",
            "If it is a fixed string in quotes, it is harmless.",
            "If it is a variable, follow it back to its source.",
            "Watch specifically for text pulled out of a config file, a network response, or "
            "anything a user typed. Those are the dangerous cases.",
        ],
        say="This turns text into running code. Anyone who can influence that text can make "
            "the program do anything.",
        fix="Replace it with something that only does the one specific job needed -- "
            "ast.literal_eval for plain data, a dictionary lookup for choosing between "
            "options, or direct parsing for a known format.",
    ),
    "builtin.pickle-load": Explanation(
        what="The code loads saved data using Python's 'pickle' format.",
        why="Pickle is not just a data format. A pickle file is allowed to contain "
            "instructions saying 'when you load me, run this code' -- and Python obeys, "
            "before you get a chance to inspect anything. Loading a pickle from an untrusted "
            "source is equivalent to running a program someone else wrote.",
        check=[
            "Open the file at the reported line.",
            "Find where the data being loaded comes from.",
            "If it is a file the program wrote itself and no one else can touch, it is "
            "acceptable.",
            "If it arrives over a network, comes from an upload, or sits in a location other "
            "users can write to, it is a real bug.",
        ],
        say="Loading pickle data runs whatever code is hidden inside it. If that data comes "
            "from anywhere untrusted, the attacker's code runs.",
        fix="Use JSON for data that crosses a trust boundary. JSON can only describe data, "
            "never instructions.",
    ),
    "builtin.yaml-unsafe-load": Explanation(
        what="The code reads a YAML config file in a mode that can build arbitrary Python "
             "objects.",
        why="Plain yaml.load is allowed to construct any Python object the file names, which "
            "can be turned into running code. The safe mode reads only ordinary data -- text, "
            "numbers, lists, dictionaries.",
        check=[
            "Open the file at the reported line.",
            "Check whether yaml.load was given Loader=yaml.SafeLoader.",
            "If not, ask where the YAML file comes from. Bundled with the project is low "
            "risk; supplied by a user is a real bug.",
        ],
        say="This reads a YAML file in a mode that lets the file create Python objects, which "
            "can lead to code running. The safe loader does the same job without that risk.",
        fix="Use yaml.safe_load(...), or pass Loader=yaml.SafeLoader.",
    ),
    "builtin.weak-hash": Explanation(
        what="The code uses MD5 or SHA-1 to make a fingerprint of some data.",
        why="Both are old and broken in a specific way: it is now practical to construct two "
            "different inputs with the same fingerprint. So a fingerprint no longer proves "
            "which input produced it. That breaks anything relying on it -- password storage, "
            "signatures, 'has this file changed' checks.",
        check=[
            "Open the file at the reported line.",
            "Work out what the fingerprint is used for.",
            "Passwords, signatures, or security checks: real bug.",
            "A cache key, a random-looking filename, or a non-security lookup: technically "
            "fine, though still worth flagging as cleanup.",
        ],
        say="MD5 and SHA-1 are broken -- two different inputs can produce the same "
            "fingerprint. Anything trusting that fingerprint to prove identity is unsafe.",
        fix="Use SHA-256 for general hashing. For passwords specifically, use a dedicated "
            "password hash like bcrypt or argon2 -- plain SHA-256 is also wrong there.",
    ),
    "builtin.tls-verify-disabled": Explanation(
        what="The code makes an HTTPS request but turns off the check that the server is who "
             "it claims to be.",
        why="HTTPS does two things: it encrypts the traffic, and it proves you are talking to "
            "the real server. Turning off verification keeps the encryption but drops the "
            "proof. Anyone positioned between you and the server -- on the same wifi, at an "
            "ISP -- can pretend to be that server, read everything sent, and send back "
            "whatever they like.",
        check=[
            "Open the file at the reported line and confirm verify=False is really there.",
            "Check what is being sent and received. Credentials or update files make it "
            "serious.",
            "Look for a nearby comment explaining it -- sometimes it is a deliberate choice "
            "for talking to a server with a self-signed certificate.",
        ],
        say="This turns off the check that you are talking to the real server. Someone in the "
            "middle can impersonate it, read what is sent, and control what comes back.",
        fix="Remove verify=False. If the server uses a private certificate, point verify at "
            "that certificate file instead of disabling the check entirely.",
    ),
    "builtin.debug-enabled": Explanation(
        what="A web framework is started with debug mode switched on.",
        why="Debug mode is a development convenience. It shows full error pages including "
            "source code, and in Flask it can expose an interactive console that runs Python "
            "on the server. Useful on your laptop, dangerous if it reaches a real deployment.",
        check=[
            "Open the file at the reported line.",
            "Decide whether this file is what actually runs in production. An example script "
            "or local dev launcher is fine.",
            "If it is the real startup path, or the setting comes from a config that could be "
            "wrong in production, it matters.",
        ],
        say="Debug mode leaks source code in error pages and can expose a console that runs "
            "commands on the server. It should never be on outside development.",
        fix="Drive it from an environment variable that defaults to off, so production has to "
            "opt in rather than opt out.",
    ),
    "builtin.insecure-temp": Explanation(
        what="The code uses tempfile.mktemp to pick a temporary filename.",
        why="mktemp only chooses a name -- it does not create the file. In the gap between "
            "choosing the name and using it, another program can create that file first, and "
            "your program then writes into something it does not control.",
        check=[
            "Open the file at the reported line.",
            "Confirm it is mktemp and not mkstemp -- one letter apart, very different.",
            "This is a lower-severity issue and needs specific timing to exploit, but the "
            "safe version is a drop-in replacement, so there is no reason to keep it.",
        ],
        say="This picks a temporary filename without creating it, leaving a gap where another "
            "program can create that file first and hijack what gets written.",
        fix="Use tempfile.mkstemp or tempfile.NamedTemporaryFile, which create the file "
            "atomically.",
    ),
    "builtin.xml-parse": Explanation(
        what="The code parses XML using Python's built-in XML library.",
        why="XML files can define shortcuts that expand into other content, including the "
            "contents of files on the server. A malicious XML file can use this to read files "
            "it should not, or to expand into something enormous and exhaust memory.",
        check=[
            "Open the file at the reported line.",
            "Find where the XML comes from. Bundled with the project: low risk. Uploaded or "
            "fetched from elsewhere: real bug.",
            "Note that modern Python versions block some of these attacks by default, so "
            "check which behaviour applies before claiming it is exploitable.",
        ],
        say="XML can be crafted to make the parser read files off the server or blow up "
            "memory. The defusedxml library blocks that.",
        fix="Use the defusedxml package in place of the standard library XML modules.",
    ),
    "builtin.hardcoded-secret": Explanation(
        what="A password, API key, or token appears to be written directly into the source "
             "code.",
        why="Anything in source code is in version history, in every clone, and visible to "
            "everyone with repository access -- forever, even if deleted later, because old "
            "commits keep it. If the project is public, assume it is already collected by "
            "automated scanners.",
        check=[
            "Open the file at the reported line.",
            "Decide whether it is a real credential or a placeholder. Test files, examples "
            "and documentation are full of fake ones.",
            "If it looks real, check whether it still works -- and if so, the priority is "
            "rotating it (replacing it at the provider), not just deleting the line.",
            "Deleting the line alone does not help. The value stays in git history.",
        ],
        say="A credential is written into the source. Anyone with repository access has it, "
            "and git history keeps it even after the line is removed.",
        fix="Read it from an environment variable or a secret manager, and rotate the exposed "
            "value at the provider.",
    ),
}


# When a Semgrep or other external rule fires, its ID is not in the table above. These
# keyword matches give a useful explanation rather than nothing.
KEYWORD_FALLBACKS = (
    (("sql", "sqli"), "builtin.eval-exec"),
    (("command-injection", "shell", "subprocess", "os-system"), "builtin.subprocess-shell-true"),
    (("eval", "exec", "code-injection"), "builtin.eval-exec"),
    (("pickle", "deserial", "marshal"), "builtin.pickle-load"),
    (("yaml",), "builtin.yaml-unsafe-load"),
    (("md5", "sha1", "weak-hash", "insecure-hash"), "builtin.weak-hash"),
    (("verify", "tls", "ssl", "certificate"), "builtin.tls-verify-disabled"),
    (("debug",), "builtin.debug-enabled"),
    (("tempfile", "tmp", "mktemp"), "builtin.insecure-temp"),
    (("xml", "xxe"), "builtin.xml-parse"),
    (("secret", "password", "token", "credential", "api-key", "apikey"),
     "builtin.hardcoded-secret"),
)

GENERIC = Explanation(
    what="A scanner flagged this line as matching a known risky pattern.",
    why="This tool does not have a plain-language write-up for this particular rule, so the "
        "scanner's own message above is the best description available.",
    check=[
        "Open the file at the reported line and read the surrounding code.",
        "Search the web for the rule ID shown -- scanner rules almost always have "
        "documentation explaining what they look for and why.",
        "Work out whether any value involved comes from outside the program. That is usually "
        "what separates a real bug from a false alarm.",
    ],
    say="A scanner matched a known risky pattern here. I would need to read the rule's "
        "documentation before saying how serious it is.",
)


def for_finding(rule_id: str, message: str = "") -> Explanation:
    """Best available explanation for a rule, falling back to keyword matching."""
    if rule_id in EXPLANATIONS:
        return EXPLANATIONS[rule_id]

    haystack = ("%s %s" % (rule_id, message)).lower()
    for keywords, target in KEYWORD_FALLBACKS:
        if any(k in haystack for k in keywords):
            return EXPLANATIONS[target]
    return GENERIC


# --------------------------------------------------------------------------- verdicts

VERDICTS = {
    "REACHABLE": (
        "Something outside the program can actually get here.",
        "Starting from a real entry point -- a web address, a command, a scheduled job -- "
        "there is a chain of function calls that arrives at this line. The chain is printed "
        "below. This is the group worth your attention.",
    ),
    "UNREACHABLE": (
        "Nothing appears to call this code.",
        "The line matched a risky pattern, but no path was found from any entry point, so it "
        "looks like dead code or a test fixture. Worth fixing eventually, not urgent. Note "
        "the tool can be wrong here -- if the code is called in a way static analysis cannot "
        "see, this verdict is too optimistic.",
    ),
    "UNKNOWN": (
        "The tool could not tell.",
        "Usually because the code sits at the top level of a file rather than inside a "
        "function, or because it is public API that outside code could call even though "
        "nothing inside this project does. Deliberately not called UNREACHABLE -- saying "
        "'safe' when unsure is the one mistake worth avoiding.",
    ),
}


def for_verdict(status: str):
    return VERDICTS.get(status, ("", ""))


def path_in_words(path: List[str], entry_reason: str = "") -> str:
    """Turn a call path into a sentence a person can follow."""
    if not path:
        return ""

    def short(qual: str) -> str:
        return qual.rsplit(".", 1)[-1]

    start = short(path[0])
    trigger = _trigger_phrase(entry_reason, start)

    if len(path) == 1:
        return "%s, and that is where the flagged line is." % trigger

    hops = " which calls ".join("`%s`" % short(p) for p in path[1:])
    return "%s, which calls %s -- and that is where the flagged line is." % (trigger, hops)


def _trigger_phrase(entry_reason: str, start: str) -> str:
    reason = (entry_reason or "").lower()
    if "route" in reason or "urlpatterns" in reason or "app." in reason:
        return "Someone visits a web address handled by `%s`" % start
    if "__main__" in reason:
        return "Someone runs this file directly, which calls `%s`" % start
    if "console_script" in reason:
        return "Someone types the command that runs `%s`" % start
    if "public api" in reason or "re-exported" in reason:
        return "Any project using this library can call `%s`" % start
    if "task" in reason or "celery" in reason:
        return "A background job runs `%s`" % start
    return "Something calls `%s`" % start

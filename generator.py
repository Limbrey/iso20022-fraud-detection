"""
generator.py — pacs.008 message factory
Produces realistic interbank credit transfers with optional fraud injection.

Each sending bank has its own profile (typical amount range, preferred
corridors, activity level) so ML anomaly detection has distinct baselines
to learn from.
"""
import uuid
import random
import string
from dataclasses import dataclass, field
from decimal import Decimal
from datetime import datetime, date
from typing import Optional

from pyiso20022.pacs.pacs_008_001_08.pacs_008_001_08 import (
    Document, FitoFicustomerCreditTransferV08, GroupHeader93,
    CreditTransferTransaction39, BranchAndFinancialInstitutionIdentification6,
    FinancialInstitutionIdentification18, CashAccount38,
    AccountIdentification4Choice, ActiveCurrencyAndAmount,
    PartyIdentification135, PaymentIdentification7,
    ChargeBearerType1Code, SettlementInstruction7, SettlementMethod1Code,
    PostalAddress24, AddressType2Code,
)
from xsdata.models.datatype import XmlDate, XmlDateTime
from xsdata.formats.dataclass.serializers import XmlSerializer
from xsdata.formats.dataclass.serializers.config import SerializerConfig

# ── Sending bank profiles ─────────────────────────────────────────────────────
# Each bank has:
#   bic, name          — identity
#   amount_mu/sigma    — log-normal parameters for payment amounts
#   amount_min/max     — hard clamp
#   weight             — how often this bank sends (relative frequency)
#   preferred_creditors— BICs this bank mostly pays (realistic corridors)
#
# This gives the ML distinct per-sender baselines to learn.

SENDER_PROFILES = [
    {
        "bic":   "BARCGB22",
        "name":  "Barclays Bank",
        "amount_mu":    8.5,    # log-normal mean → ~£4,900 typical
        "amount_sigma": 1.2,
        "amount_min":   500,
        "amount_max":   250000,
        "weight": 20,           # large bank — lots of traffic
        "preferred_creditors": ["HBUKGB4B", "LOYDGB2L", "NWBKGB2L", "DEUTDEDB", "BNPAFRPP"],
    },
    {
        "bic":   "HBUKGB4B",
        "name":  "HSBC Bank",
        "amount_mu":    9.2,    # ~£9,900 typical — large corporate bank
        "amount_sigma": 1.4,
        "amount_min":   1000,
        "amount_max":   500000,
        "weight": 18,
        "preferred_creditors": ["BARCGB22", "CITIUS33", "CHASUS33", "ABNANL2A", "INGBNL2A"],
    },
    {
        "bic":   "LOYDGB2L",
        "name":  "Lloyds Bank",
        "amount_mu":    7.8,    # ~£2,400 typical — retail-heavy
        "amount_sigma": 1.1,
        "amount_min":   100,
        "amount_max":   150000,
        "weight": 16,
        "preferred_creditors": ["BARCGB22", "NWBKGB2L", "SANBGB2L", "NAIAGB21"],
    },
    {
        "bic":   "NWBKGB2L",
        "name":  "NatWest Bank",
        "amount_mu":    7.5,
        "amount_sigma": 1.0,
        "amount_min":   100,
        "amount_max":   100000,
        "weight": 14,
        "preferred_creditors": ["LOYDGB2L", "BARCGB22", "RBSSGB2L", "MIDLGB22"],
    },
    {
        "bic":   "SANBGB2L",
        "name":  "Santander UK",
        "amount_mu":    7.2,    # ~£1,300 typical — retail mortgage focus
        "amount_sigma": 0.9,
        "amount_min":   50,
        "amount_max":   80000,
        "weight": 10,
        "preferred_creditors": ["LOYDGB2L", "BARCGB22", "BSCHESMM"],
    },
    {
        "bic":   "MONZGB2L",
        "name":  "Monzo Bank",
        "amount_mu":    6.2,    # ~£490 typical — fintech, small frequent payments
        "amount_sigma": 0.8,
        "amount_min":   5,
        "amount_max":   20000,
        "weight": 8,
        "preferred_creditors": ["BARCGB22", "LOYDGB2L", "STRLGB2L"],
    },
    {
        "bic":   "STRLGB2L",
        "name":  "Starling Bank",
        "amount_mu":    6.5,
        "amount_sigma": 0.9,
        "amount_min":   10,
        "amount_max":   25000,
        "weight": 7,
        "preferred_creditors": ["BARCGB22", "MONZGB2L", "LOYDGB2L"],
    },
    {
        "bic":   "METRGB21",
        "name":  "Metro Bank",
        "amount_mu":    7.0,
        "amount_sigma": 1.0,
        "amount_min":   100,
        "amount_max":   50000,
        "weight": 5,
        "preferred_creditors": ["BARCGB22", "NWBKGB2L", "COULGB22"],
    },
    {
        "bic":   "DEUTDEDB",
        "name":  "Deutsche Bank",
        "amount_mu":    10.5,   # ~£36k typical — large corporate/institutional
        "amount_sigma": 1.5,
        "amount_min":   5000,
        "amount_max":   2000000,
        "weight": 8,
        "preferred_creditors": ["HBUKGB4B", "BARCGB22", "BNPAFRPP", "ABNANL2A"],
    },
    {
        "bic":   "BNPAFRPP",
        "name":  "BNP Paribas",
        "amount_mu":    10.2,
        "amount_sigma": 1.4,
        "amount_min":   2000,
        "amount_max":   1500000,
        "weight": 6,
        "preferred_creditors": ["DEUTDEDB", "HBUKGB4B", "CRLYFRPP", "BARCGB22"],
    },
    {
        "bic":   "NSHBGB2L",
        "name":  "Northshire Community Bank",
        "amount_mu":    6.8,    # small community bank — modest amounts
        "amount_sigma": 0.9,
        "amount_min":   50,
        "amount_max":   50000,
        "weight": 4,
        "preferred_creditors": ["BARCGB22", "LOYDGB2L", "NWBKGB2L", "NAIAGB21"],
    },
]

# Build weighted lookup for fast sampling
_SENDER_BICS  = [p["bic"]    for p in SENDER_PROFILES]
_SENDER_WEIGHTS = [p["weight"] for p in SENDER_PROFILES]
_SENDER_BY_BIC  = {p["bic"]: p for p in SENDER_PROFILES}

# ── Creditor reference data ───────────────────────────────────────────────────

ALL_CREDITOR_BICS = list({bic for p in SENDER_PROFILES for bic in p["preferred_creditors"]} |
                          {p["bic"] for p in SENDER_PROFILES})

COMPANY_NAMES = [
    "Thornfield Manufacturing Ltd", "Greenway Logistics PLC",
    "Heatherstone Retail Group", "Oakmoor Technology Solutions",
    "Riverbank Financial Services", "Alderman Consulting Ltd",
    "Pennine Trading Co Ltd", "Clearwater Capital Ltd",
    "Moorfield Properties Ltd", "Lakeside Hospitality Group",
    "Ironbridge Engineering Ltd", "Silverstone Investments PLC",
    "Highbury Media Group Ltd", "Fernwood Healthcare Ltd",
    "Broadhurst Construction Ltd", "Ashfield Energy Services",
    "Crestwood Pharmaceuticals", "Millbrook Foods Ltd",
    "Stonegate Insurance Group", "Windermere Renewables Ltd",
    "Castleton Asset Management", "Greystone Capital Partners",
    "Whitmore Fund Services Ltd", "Kingsbridge Trading Co",
    "Hartwell Consumer Finance", "Redwood Infrastructure PLC",
]

PURPOSE_CODES = ["GDDS", "SUPP", "SALA", "RENT", "TAXS", "INVS", "DIVI", "LOAN"]

# Sanctioned / high-risk BICs for fraud injection
SANCTIONED_BICS = [
    ("KOBAKPPY", "Korea Commerce Bank KP"),
    ("BTEJIRTE", "Bank Tejarat IR"),
    ("TEBEIRTE", "Bank Tejarat IR Alt"),
    ("BSYRSYDA", "Bank of Syria"),
    ("BCUBCUHA", "Banco Central Cuba"),
]

INVALID_BICS = ["XXXXGB00", "FAKEUS99", "BADDBIC1", "NOTABANX", "XXXXXXXX"]


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class GeneratedMessage:
    xml: str
    msg_id: str
    uetr: str
    amount: float
    currency: str
    debtor_name: str
    debtor_bic: str
    creditor_name: str
    creditor_bic: str
    is_fraud: bool
    fraud_type: Optional[str]
    fraud_description: Optional[str]
    timestamp: datetime = field(default_factory=datetime.now)
    settlement_date: Optional[date] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _random_iban(prefix="GB") -> str:
    check = random.randint(10, 99)
    sort  = "".join(random.choices(string.digits, k=6))
    acct  = "".join(random.choices(string.digits, k=8))
    return f"{prefix}{check}{sort}{acct}"


def _make_fi(bic: str) -> BranchAndFinancialInstitutionIdentification6:
    return BranchAndFinancialInstitutionIdentification6(
        fin_instn_id=FinancialInstitutionIdentification18(bicfi=bic)
    )


def _make_account(iban: str) -> CashAccount38:
    return CashAccount38(id=AccountIdentification4Choice(iban=iban))


def _xml_serializer() -> XmlSerializer:
    return XmlSerializer(config=SerializerConfig(pretty_print=True))


# ── Generator class ───────────────────────────────────────────────────────────

class Pacs008Generator:
    def __init__(self, config: dict):
        self.cfg       = config
        self.bank_cfg  = config.get("bank", {})
        self.fraud_cfg = config.get("fraud", {})
        self._serializer    = _xml_serializer()
        self._fraud_weights = self._build_fraud_weights()

    def _build_fraud_weights(self) -> list:
        types  = self.fraud_cfg.get("types", {})
        result = []
        for name, info in types.items():
            if info.get("enabled", True):
                result.append((name, info.get("weight", 0.1), info.get("description", "")))
        total = sum(w for _, w, _ in result)
        return [(n, w / total, d) for n, w, d in result]

    def _pick_fraud_type(self) -> tuple:
        r, cumulative = random.random(), 0.0
        for name, weight, desc in self._fraud_weights:
            cumulative += weight
            if r < cumulative:
                return name, desc
        return self._fraud_weights[-1][0], self._fraud_weights[-1][2]

    def _pick_sender(self) -> dict:
        """Pick a sending bank weighted by activity level."""
        return random.choices(SENDER_PROFILES, weights=_SENDER_WEIGHTS, k=1)[0]

    def _sender_amount(self, profile: dict) -> Decimal:
        """Draw an amount from this sender's log-normal distribution."""
        raw = random.lognormvariate(profile["amount_mu"], profile["amount_sigma"])
        raw = max(profile["amount_min"], min(profile["amount_max"], raw))
        return Decimal(f"{raw:.2f}")

    def _pick_creditor(self, sender_profile: dict) -> tuple:
        """
        80% of the time pick from the sender's preferred corridors,
        20% pick any bank — realistic long-tail behaviour.
        """
        if random.random() < 0.8 and sender_profile["preferred_creditors"]:
            creditor_bic = random.choice(sender_profile["preferred_creditors"])
        else:
            creditor_bic = random.choice(ALL_CREDITOR_BICS)
        creditor_name = random.choice(COMPANY_NAMES)
        return creditor_bic, creditor_name

    def generate(self) -> GeneratedMessage:
        fraud_rate = self.fraud_cfg.get("overall_rate", 0.05)
        is_fraud   = self.fraud_cfg.get("enabled", True) and random.random() < fraud_rate
        fraud_type = None
        fraud_desc = None
        currency   = self.bank_cfg.get("currency", "GBP")

        # Pick sender from pool of banks
        sender         = self._pick_sender()
        debtor_bic     = sender["bic"]
        debtor_name    = sender["name"]

        # Pick creditor using sender's corridor preferences
        creditor_bic, creditor_name = self._pick_creditor(sender)

        # Draw amount from sender's own distribution
        amount     = self._sender_amount(sender)
        sttlm_date = date.today()

        if is_fraud:
            fraud_type, fraud_desc = self._pick_fraud_type()
            amount, creditor_bic, creditor_name = self._apply_fraud(
                fraud_type, amount, creditor_bic, creditor_name, sender
            )

        msg_id = str(uuid.uuid4()).replace("-", "")[:35]
        uetr   = str(uuid.uuid4())

        txn = CreditTransferTransaction39(
            pmt_id=PaymentIdentification7(
                instr_id=str(uuid.uuid4())[:35],
                end_to_end_id=str(uuid.uuid4())[:35],
                uetr=uetr,
            ),
            intr_bk_sttlm_amt=ActiveCurrencyAndAmount(value=amount, ccy=currency),
            intr_bk_sttlm_dt=XmlDate(sttlm_date.year, sttlm_date.month, sttlm_date.day),
            chrg_br=random.choice([
                ChargeBearerType1Code.SHAR,
                ChargeBearerType1Code.DEBT,
                ChargeBearerType1Code.CRED,
            ]),
            dbtr=PartyIdentification135(nm=debtor_name[:140]),
            dbtr_acct=_make_account(_random_iban("GB")),
            dbtr_agt=_make_fi(debtor_bic),
            cdtr=PartyIdentification135(nm=creditor_name[:140]),
            cdtr_acct=_make_account(_random_iban("GB")),
            cdtr_agt=_make_fi(creditor_bic),
        )

        doc = Document(
            fito_ficstmr_cdt_trf=FitoFicustomerCreditTransferV08(
                grp_hdr=GroupHeader93(
                    msg_id=msg_id,
                    cre_dt_tm=XmlDateTime.now(),
                    nb_of_txs="1",
                    sttlm_inf=SettlementInstruction7(sttlm_mtd=SettlementMethod1Code.CLRG),
                ),
                cdt_trf_tx_inf=[txn],
            )
        )

        xml = self._serializer.render(doc)

        return GeneratedMessage(
            xml=xml,
            msg_id=msg_id,
            uetr=uetr,
            amount=float(amount),
            currency=currency,
            debtor_name=debtor_name,
            debtor_bic=debtor_bic,
            creditor_name=creditor_name,
            creditor_bic=creditor_bic,
            is_fraud=is_fraud,
            fraud_type=fraud_type,
            fraud_description=fraud_desc,
            settlement_date=sttlm_date,
        )

    def _apply_fraud(self, fraud_type, amount, creditor_bic, creditor_name, sender):
        if fraud_type == "invalid_bic":
            creditor_bic = random.choice(INVALID_BICS)

        elif fraud_type == "sanctioned_country":
            bic, name    = random.choice(SANCTIONED_BICS)
            creditor_bic  = bic
            creditor_name = name

        elif fraud_type == "round_amount":
            amount = Decimal(str(random.choice([
                10000, 15000, 20000, 25000, 50000, 100000
            ])))

        elif fraud_type == "amount_spike":
            # Spike is relative to THIS sender's normal max — makes it meaningful
            normal_max = sender["amount_max"]
            amount = Decimal(f"{random.uniform(normal_max * 3, normal_max * 8):.2f}")

        elif fraud_type == "dormant_account":
            pass   # signal is the account gap — harness tracks this externally

        elif fraud_type == "rapid_succession":
            pass   # signal is timing — harness handles burst cadence

        return amount, creditor_bic, creditor_name

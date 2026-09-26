from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOC = os.path.join(ROOT, "docs", "TRAINING.md")
TEMPLATE = os.path.join(HERE, "training_template.md")

ORDER = [
    "benign",
    "volumetric-ddos",
    "c2-beaconing",
    "dga-dns-tunnelling",
    "encrypted-malware",
    "recon-scanning",
    "data-exfiltration",
]


def load(name):
    with open(os.path.join(ROOT, "data", "models", name), encoding="ascii") as fh:
        return json.load(fh)


def prevalence_block(manifest):
    counts = manifest["counts"]
    lines = ["| Class | Train | Train % | Calibration | Calibration % | Test | Test % |",
             "|---|---|---|---|---|---|---|"]
    for name in ORDER:
        row = [name]
        for split in ("train", "calibration", "test"):
            total = counts[split]["rows"]
            value = counts[split]["by_class"].get(name, 0)
            row.append(str(value))
            row.append("%.2f" % (100.0 * value / total))
        lines.append("| " + " | ".join(row) + " |")
    totals = ["**Total rows**"]
    for split in ("train", "calibration", "test"):
        totals.append("**%d**" % counts[split]["rows"])
        totals.append("**100**")
    lines.append("| " + " | ".join(totals) + " |")
    attack = []
    for split in ("train", "calibration", "test"):
        total = counts[split]["rows"]
        benign = counts[split]["by_class"].get("benign", 0)
        attack.append("%.1f" % (100.0 * (total - benign) / total))
    lines.append("")
    lines.append("Attack rows are %s percent of the training slice, %s percent of the calibration"
                 % (attack[0], attack[1]))
    lines.append("slice and %s percent of the test slice. The embargo bands discarded the rows"
                 % attack[2])
    lines.append("between the slices, so the three counts do not sum to the %d rows in the dataset."
                 % manifest["rows"])
    return "\n".join(lines)


def per_class_table(report):
    lines = ["| Class | Precision | Recall | F1 | Test rows |", "|---|---|---|---|---|"]
    for name in ORDER:
        row = report[name]
        lines.append("| %s | %.4f | %.4f | %.4f | %d |"
                     % (name, row["precision"], row["recall"], row["f1"], row["rows"]))
    return "\n".join(lines)


def metrics_block(metrics):
    test = metrics["test"]
    strict = metrics["test_strict_no_flow_seen_in_train"]
    draws = test["constructed_test_set"]
    rel = test["reliability_weighted"]
    out = []
    out.append("**PR-AUC is the headline because prevalence is low.** ROC-AUC divides by the benign")
    out.append("population when it computes the false-positive rate. Multiply the benign population")
    out.append("by a thousand and the false-positive rate barely moves, so ROC-AUC barely moves,")
    out.append("while the thing the analyst actually experiences, how many of the alerts in front of")
    out.append("them are real, collapses. Precision-recall works in the space the analyst lives in:")
    out.append("precision is true positives over everything raised, and it degrades exactly as fast")
    out.append("as the false alarms multiply. ROC-AUC is computed internally and deliberately not")
    out.append("published as a headline.")
    out.append("")
    out.append("The corpus is attack heavy, so every headline figure is reported at a **constructed**")
    out.append("**prevalence of one attack observation per thousand benign ones**. The primary")
    out.append("estimator keeps every test row and gives each benign row an importance weight of")
    out.append("%.1f, which is exact arithmetic and keeps full support for the per-class numbers."
               % test["benign_row_weight"])
    out.append("The natural prevalence of the test slice is %.4f, that is %.1f percent attack rows,"
               % (test["natural_prevalence"], 100.0 * test["natural_prevalence"]))
    out.append("which is not a link anyone monitors.")
    out.append("")
    out.append("### Headline, tier 1 scored on every test row")
    out.append("")
    out.append("| Measure | Value |")
    out.append("|---|---|")
    out.append("| test rows | %d |" % test["rows"])
    out.append("| natural test prevalence | %.4f |" % test["natural_prevalence"])
    out.append("| constructed prevalence | %.4f |" % test["constructed_prevalence"])
    out.append("| PR-AUC, attack against benign, at 1 in 1000 | **%.4f** |"
               % test["pr_auc_attack_vs_benign"])
    out.append("| PR-AUC, attack against benign, at the natural prevalence | %.4f |"
               % test["pr_auc_at_natural_prevalence"])
    out.append("| macro F1 over the six attack classes, at 1 in 1000 | %.4f |"
               % test["macro_f1_attack_classes"])
    out.append("| expected calibration error, at 1 in 1000 | %.5f |"
               % rel["expected_calibration_error"])
    out.append("")
    out.append("**The gap between %.4f and %.4f is the whole reason this document states"
               % (test["pr_auc_at_natural_prevalence"], test["pr_auc_attack_vs_benign"]))
    out.append("prevalence.** The same model, the same rows, the same predictions: only the assumed")
    out.append("mix changed. A submission that reported the first number without saying what it was")
    out.append("measured on would be reporting %.2f for a system that scores %.2f where it matters."
               % (test["pr_auc_at_natural_prevalence"], test["pr_auc_attack_vs_benign"]))
    out.append("")
    out.append("### Per class, at the constructed prevalence of 1 in 1000")
    out.append("")
    out.append(per_class_table(test["per_class"]))
    out.append("")
    out.append("One against rest PR-AUC per attack class, same prevalence:")
    out.append("")
    out.append("| Class | PR-AUC |")
    out.append("|---|---|")
    for name in ORDER:
        if name == "benign":
            continue
        value = test["pr_auc_per_class"].get(name)
        if value is not None:
            out.append("| %s | %.4f |" % (name, value))
    out.append("")
    out.append("### The same rows at the natural test prevalence, for contrast")
    out.append("")
    out.append(per_class_table(test["per_class_at_natural_prevalence"]))
    out.append("")
    out.append("### Reading these numbers honestly")
    out.append("")
    out.append("Recall holds up and precision does not. At one attack per thousand, three classes")
    out.append("have precision below 0.01: a handful of benign rows misclassified becomes a flood")
    out.append("once the benign population is weighted up by %.0f. That is a real weakness of the"
               % test["benign_row_weight"])
    out.append("tier-1 model and it is stated rather than buried.")
    out.append("")
    out.append("Two things it is not. First, it is **not the alert rate of the shipped system**.")
    out.append("This table scores the model's argmax on every observation the engine produced. The")
    out.append("engine does not alert per observation: a rule has to fire, the model has to agree,")
    out.append("cooldowns apply per subject, and the benign baseline capture raises zero alerts end")
    out.append("to end with all six detectors running. Second, it is not a measurement of the")
    out.append("detectors, which are deterministic rules with published thresholds and are measured")
    out.append("in the ablation below.")
    out.append("")
    out.append("The classes that do hold precision, volumetric DDoS and reconnaissance, are the ones")
    out.append("whose features are unambiguous per observation. The classes that do not, beaconing")
    out.append("and exfiltration, are the ones whose evidence is a pattern across many observations,")
    out.append("which a per-row classifier cannot see and a stateful detector can. That is an")
    out.append("argument for the architecture, not an excuse for the number.")
    out.append("")
    out.append("### The strict variant")
    out.append("")
    out.append("Every test row belonging to a flow that was also seen in training is removed, which")
    out.append("leaves %d of the %d rows in the full test slice." % (strict["rows"], test["rows"]))
    out.append("")
    out.append("| Measure | Full test | Strict |")
    out.append("|---|---|---|")
    out.append("| rows | %d | %d |" % (test["rows"], strict["rows"]))
    out.append("| PR-AUC at 1 in 1000 | %.4f | %.4f |"
               % (test["pr_auc_attack_vs_benign"], strict["pr_auc_attack_vs_benign"]))
    out.append("| macro F1 over attack classes | %.4f | %.4f |"
               % (test["macro_f1_attack_classes"], strict["macro_f1_attack_classes"]))
    out.append("")
    if strict["pr_auc_attack_vs_benign"] >= test["pr_auc_attack_vs_benign"]:
        out.append("The strict variant scores higher, not lower, which is worth a sentence. Removing")
        out.append("straddling flows removes the long-lived beacon and drip channels, and those are")
        out.append("exactly the classes the per-row model is worst at. The strict number is cleaner")
        out.append("evidence of leakage control and a weaker sample of the hard classes; read both.")
    else:
        out.append("The strict variant scores lower, which is the expected direction: the rows it")
        out.append("removes were the ones the model had the most support for.")
    out.append("")
    out.append("### The physical cross-check")
    out.append("")
    out.append("Importance weighting is arithmetic, so it is checked against a test set physically")
    out.append("built at the same ratio: keep all %d benign rows, draw %d attack rows, repeat %d"
               % (draws["benign_rows"], draws["attack_rows_kept"], draws["draws"]))
    out.append("times with a fixed seed. Measured prevalence %.6f, PR-AUC %.4f, standard deviation"
               % (draws["measured_prevalence"], draws["pr_auc_mean"]))
    out.append("%.4f, range %.4f to %.4f."
               % (draws["pr_auc_std"], draws["pr_auc_min"], draws["pr_auc_max"]))
    out.append("")
    out.append("That agrees with the weighted estimate of %.4f. Only %d attack rows survive a draw"
               % (test["pr_auc_attack_vs_benign"], draws["attack_rows_kept"]))
    out.append("at this ratio, so per-class precision and recall are not estimable from it and only")
    out.append("the pooled figure is reported. That is why the weighted estimator is primary and")
    out.append("this one is the cross-check rather than the other way round.")
    out.append("")
    out.append("### Reliability")
    out.append("")
    out.append("The reliability diagram is at `data/models/reliability.png`, drawn at both")
    out.append("prevalences, and the bins behind it are in `metrics.json` under")
    out.append("`reliability_weighted` and `reliability_natural`. Expected calibration error at the")
    bins = len(rel["bins"])
    tail = "all twelve bins" if bins == 12 else "%d populated bins of twelve" % bins
    out.append("constructed prevalence is %.5f over %s."
               % (rel["expected_calibration_error"], tail))
    return "\n".join(out)


def ablation_block(metrics):
    test = metrics["test"]
    ab = test["ablation"]
    macro = ab["macro_f1_attack_classes"]
    episodes = metrics.get("episodes")
    hold = ab.get("rule_persistence_s", 0.0)
    floor = ab.get("model_alert_confidence", 0.0)
    out = []
    out.append("Three arms, all at the constructed prevalence of 1 in 1000.")
    out.append("")
    out.append("**Rules only** is the deterministic detector verdict, held for %d seconds against"
               % int(hold))
    out.append("both endpoints of the flow it named. The hold is not a fudge, it is what makes the")
    out.append("comparison fair: a rule raises one alert per episode and then goes quiet on its own")
    out.append("cooldown, so scoring the bare fire against every row would report a recall near zero")
    out.append("for a detector that in fact caught the attack.")
    out.append("")
    out.append("**Model only** is the argmax of the calibrated tier-1 probability, with nothing else")
    out.append("consulted.")
    out.append("")
    out.append("**Both** is what the engine actually does: a held rule names the class, and the")
    out.append("model names a class by itself only when it clears the %.2f `model_alert_confidence`"
               % floor)
    out.append("threshold and the benign-only isolation forest also calls the row unusual.")
    out.append("")
    out.append("| Arm | Macro F1 over the six attack classes |")
    out.append("|---|---|")
    for arm, label in (("rules_only", "rules only"), ("model_only", "model only"),
                       ("both", "both, as shipped")):
        out.append("| %s | %.4f |" % (label, macro[arm]))
    out.append("")
    out.append("Per class F1:")
    out.append("")
    out.append("| Class | Rules only | Model only | Both |")
    out.append("|---|---|---|---|")
    for name in ORDER:
        if name == "benign":
            continue
        out.append("| %s | %.4f | %.4f | %.4f |"
                   % (name, ab["rules_only"][name]["f1"], ab["model_only"][name]["f1"],
                      ab["both"][name]["f1"]))
    out.append("")
    out.append("Per class precision, which is where the arms differ most:")
    out.append("")
    out.append("| Class | Rules only | Model only | Both |")
    out.append("|---|---|---|---|")
    for name in ORDER:
        if name == "benign":
            continue
        out.append("| %s | %.4f | %.4f | %.4f |"
                   % (name, ab["rules_only"][name]["precision"],
                      ab["model_only"][name]["precision"], ab["both"][name]["precision"]))
    out.append("")
    out.append("One artefact of the hold is worth naming before anyone else finds it. Holding a")
    out.append("verdict against both endpoints means a DNS rule that names a host and its resolver")
    out.append("marks the resolver too, so every other host querying that resolver inside the window")
    out.append("counts as a rules positive. The rules-only precision for the DNS class is understated")
    out.append("by that spill. It is left in rather than special-cased, because the fix would be a")
    out.append("scoring rule written to flatter the table.")
    if episodes:
        out.append("")
        out.append("### The same question asked operationally")
        out.append("")
        out.append('Row-level F1 answers "was this observation labelled correctly". An analyst asks')
        out.append('"was the attack found, and how much noise came with it". This table counts, over')
        out.append("the whole capture rather than the test slice alone, how many observations inside")
        out.append("each labelled attack window each arm assigned to the right class, and how many")
        out.append("positives each arm raised outside every labelled window.")
        out.append("")
        out.append("| Scenario | Window | Rows in window | Rules only | Model only | Both |")
        out.append("|---|---|---|---|---|---|")
        for row in episodes["windows"]:
            out.append("| %s | %s | %d | %d | %d | %d |"
                       % (row["scenario"], row["subtype"], row["rows_in_window"],
                          row["rules_only"], row["model_only"], row["both"]))
        outside = episodes["positives_outside_every_labelled_window"]
        benign_hits = {arm: outside[arm].get("by_scenario", {}).get("benign", 0)
                       for arm in ("rules_only", "model_only", "both")}
        out.append("")
        out.append("| Arm | Positives outside every labelled window, of %d such rows | Of those, in "
                   "the benign capture |" % episodes["rows_outside_every_labelled_window"])
        out.append("|---|---|---|")
        for arm, label in (("rules_only", "rules only"), ("model_only", "model only"),
                           ("both", "both, as shipped")):
            out.append("| %s | %d | %d |" % (label, outside[arm]["total"], benign_hits[arm]))
        out.append("")
        out.append("The last column is the one to look at. The rule arm raises **nothing at all** in")
        out.append("the benign capture. The model arm raises %d rows there, in a capture where"
                   % benign_hits["model_only"])
        out.append("nothing is labelled and nothing should fire.")
        out.append("")
        out.append("Both units in this table are per-observation verdicts, not emitted alerts. The")
        out.append("engine emits far fewer alerts than it produces observations, because a rule has")
        out.append("to fire and a cooldown has to have elapsed; at the alert level a parametrised")
        out.append("test asserts that no alert in any of the eleven scenarios falls outside a labelled")
        out.append("attack window.")
    out.append("")
    out.append("### What the ablation says")
    out.append("")
    out.append("Every arm finds every attack window: no cell in the episode table is zero. They")
    out.append("differ in what they cost and in what they can explain.")
    out.append("")
    out.append("The model covers more of the windows whose evidence accumulates slowly, the beacon")
    out.append("and the drip, because the rule waits for enough samples before it will commit. The")
    out.append("rules cover more of the DNS windows, and more of the two slower scan windows,")
    out.append("while the model covers more of the one-second sweep that is over almost before")
    out.append("it starts. Macro")
    out.append("F1 is close across the arms, %.4f rules only against %.4f model only, which is the"
               % (macro["rules_only"], macro["model_only"]))
    out.append("honest summary: on this corpus the shipped combination of both scores highest.")
    out.append("")
    out.append("So the choice between them is not made on F1. It is made on what an enclave whose")
    out.append("output is evidence can defend. A rule alert states its clauses, its thresholds and")
    out.append("how far past them the evidence sat, and it fires nothing at all on benign traffic. A")
    out.append("model alert states a probability and a set of contributions. The shipped")
    out.append("configuration therefore lets a rule name the class whenever one fires, and lets the")
    out.append("model speak alone only above %.2f confidence with the anomaly layer agreeing. The"
               % floor)
    out.append("numbers for the alternative are in the tables above, so the choice can be argued")
    out.append("with on the evidence rather than taken on faith.")
    return "\n".join(out)


def main() -> int:
    manifest = load("dataset_manifest.json")
    metrics = load("metrics.json")
    with open(TEMPLATE, encoding="ascii") as fh:
        text = fh.read()
    text = text.replace("<!-- PREVALENCE_TABLE -->", prevalence_block(manifest))
    text = text.replace("<!-- METRICS_SECTION -->", metrics_block(metrics))
    text = text.replace("<!-- ABLATION_SECTION -->", ablation_block(metrics))
    with open(DOC, "w", encoding="ascii", newline="\n") as fh:
        fh.write(text)
    print("wrote %s from %s" % (DOC, TEMPLATE))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

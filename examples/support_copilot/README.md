# Support copilot example

A deterministic, offline support assistant that answers refund questions **through** Memory
Firewall. It is the smallest honest demonstration of the product's point: the copilot has no
special knowledge and no model — everything it says is rendered from chunks the guard allowed, with
citations, and when the guard allows nothing it declines rather than guessing.

```bash
python examples/support_copilot/copilot.py            # scripted conversation
python examples/support_copilot/copilot.py --interactive
```

The scripted run ingests a trusted policy and a poisoned issue comment, then asks the same question
three ways. Watch the third answer: the poison is in the corpus, the copilot can see that something
was withheld, and the answer still comes from the authoritative policy.

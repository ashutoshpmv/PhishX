# PhishX ML

The research paper specifies URL-level lexical/structural features but does not identify a named downloadable training dataset. Therefore the training dataset is kept separate from the repository and must be documented when selected.

Recommended first dataset for this implementation: a public raw URL phishing dataset. The training script below expects a CSV with:
- `url`
- `label`

Label convention:
- `0` = legitimate
- `1` = phishing

Do not commit the dataset to GitHub unless its license explicitly permits redistribution.

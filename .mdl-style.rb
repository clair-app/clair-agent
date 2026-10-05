# markdownlint (mdl) style: what lintorama's Stop hook runs over every tracked `*.md`.
# A style file cannot extend `relaxed`, so its exclusions are copied here. Same rules as
# clair-server, clair-web and whatsnew-app.
all
exclude_tag :whitespace
exclude_tag :line_length

exclude_rule 'MD006' # Lists at beginning of line
exclude_rule 'MD007' # List indentation
exclude_rule 'MD033' # Inline HTML
exclude_rule 'MD034' # Bare URL used
exclude_rule 'MD040' # Fenced code blocks should have a language specified
exclude_rule 'MD041' # First line in file should be a top level header
exclude_rule 'MD047' # File should end with a single newline character

# ADRs open with frontmatter before their H1, and the vendored skill's reference files open
# with an H2.
exclude_rule 'MD002' # First header should be a top level header
# Ordered lists are written `1. 2. 3.` throughout; the `1. 1. 1.` default reads worse raw.
exclude_rule 'MD029' # Ordered list item prefix
# Only a repeated heading under the *same* parent is a duplicate (mdl's spelling of
# `siblings_only`).
rule 'MD024', :allow_different_nesting => true

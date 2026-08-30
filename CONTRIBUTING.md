# 🤝 Contributing to SecMask

Thank you for your interest in contributing to SecMask! This document provides guidelines for contributing to the project.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Areas for Contribution](#areas-for-contribution)
- [Code of Conduct](#code-of-conduct)
- [Questions and Support](#questions-and-support)

---

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- conda or venv (recommended)
- Basic knowledge of NER, transformers, PyTorch

### Fork and Clone

```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/secmask.git
cd secmask

# Add upstream remote
git remote add upstream https://github.com/andrewandrewsen/secmask.git
```

---

## Development Setup

### 1. Create Development Environment

**Using conda (recommended):**

```bash
# Create environment
conda create -n secmask-dev python=3.11 -y
conda activate secmask-dev

# Install PyTorch
conda install pytorch torchvision torchaudio cpuonly -c pytorch

# Or for GPU
conda install pytorch torchvision torchaudio pytorch-cuda=11.8 -c pytorch -c nvidia
```

**Using venv:**

```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
# Install core dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy
```

### 3. Download Models and Data

```bash
# Download pre-trained models
python -c "from transformers import AutoTokenizer, AutoModelForTokenClassification; \
    AutoTokenizer.from_pretrained('andrewandrewsen/distilbert-secret-masker'); \
    AutoModelForTokenClassification.from_pretrained('andrewandrewsen/distilbert-secret-masker')"

# Download datasets (if contributing to training)
# Data files are in data/ directory
```

### 4. Verify Installation

```bash
# Run tests
pytest tests/

# Run inference
python infer_moe.py --in test.txt --fast-model andrewandrewsen/distilbert-secret-masker
```

---

## Code Style

### Python Style Guide

We follow **PEP 8** with some modifications:

- Line length: 100 characters (not 79)
- Use 4 spaces for indentation (no tabs)
- Use type hints for function signatures
- Docstrings for all public functions/classes

### Formatting

**Use Black for automatic formatting:**

```bash
# Format all Python files
black .

# Check formatting without modifying
black --check .
```

### Linting

**Use flake8 for linting:**

```bash
# Run flake8
flake8 --max-line-length=100 --ignore=E203,W503

# Ignore specific errors:
# E203: whitespace before ':'
# W503: line break before binary operator
```

### Type Checking

**Use mypy for type checking:**

```bash
# Run mypy
mypy --ignore-missing-imports .
```

### Example Code Style

```python
from typing import List, Optional, Tuple
import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification


def mask_text_moe(
    text: str,
    fast_model_dir: str,
    long_model_dir: Optional[str] = None,
    tau: float = 0.80,
    enable_escalation: bool = True,
    token: Optional[str] = None
) -> str:
    """
    Mask secrets in text using Mixture of Experts approach.

    Args:
        text: Input text to mask
        fast_model_dir: Path or HuggingFace ID for fast expert model
        long_model_dir: Path or HuggingFace ID for long expert model (optional)
        tau: Confidence threshold for secret detection (0-1)
        enable_escalation: Whether to escalate to long expert for complex cases
        token: HuggingFace authentication token (optional)

    Returns:
        Text with secrets replaced by [SECRET] token

    Example:
        >>> masked = mask_text_moe("API key: sk-1234567890",
        ...                        fast_model_dir="andrewandrewsen/distilbert-secret-masker")
        >>> print(masked)
        "API key: [SECRET]"
    """
    # Implementation...
    pass
```

---

## Testing Requirements

### Writing Tests

**All contributions must include tests:**

1. **Unit tests** for new functions
2. **Integration tests** for new features
3. **Regression tests** for bug fixes

### Test Structure

```python
import pytest
from infer_moe import mask_text_moe


class TestSecretMasking:
    """Test suite for secret masking functionality"""

    def test_github_token_detection(self):
        """Test that GitHub tokens are properly detected and masked"""
        text = "Token: ghp_" "1234567890abcdefghijklmnopqrstuvwxyz"
        masked = mask_text_moe(text, fast_model_dir="andrewandrewsen/distilbert-secret-masker")

        assert '[SECRET]' in masked
        assert 'ghp_' not in masked

    def test_aws_key_detection(self):
        """Test that AWS access keys are properly detected and masked"""
        text = "AWS_ACCESS_KEY_ID=AKIA" "IOSFODNN7EXAMPLE"
        masked = mask_text_moe(text, fast_model_dir="andrewandrewsen/distilbert-secret-masker")

        assert '[SECRET]' in masked
        assert 'AKIA' not in masked

    def test_no_false_positives(self):
        """Test that normal text is not masked"""
        text = "This is a normal sentence with no secrets."
        masked = mask_text_moe(text, fast_model_dir="andrewandrewsen/distilbert-secret-masker")

        assert text == masked
        assert '[SECRET]' not in masked

    @pytest.mark.parametrize("secret_type,text", [
        ("github_token", "ghp_" "1234567890abcdefghijklmnopqrstuvwxyz"),
        ("aws_key", "AKIA" "IOSFODNN7EXAMPLE"),
        ("jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
    ])
    def test_secret_types(self, secret_type, text):
        """Test detection of various secret types"""
        masked = mask_text_moe(text, fast_model_dir="andrewandrewsen/distilbert-secret-masker")
        assert '[SECRET]' in masked
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_filters.py

# Run specific test
pytest tests/test_filters.py::TestFilters::test_github_token

# Run with verbose output
pytest -v

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"
```

### Test Coverage

**Aim for >80% code coverage:**

```bash
# Generate coverage report
pytest --cov=. --cov-report=term-missing

# View HTML report
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

---

## Pull Request Process

### 1. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-123-description
```

### 2. Make Changes

```bash
# Make your changes
# ...

# Format code
black .

# Run linters
flake8 --max-line-length=100

# Run tests
pytest
```

### 3. Commit Changes

**Follow conventional commit format:**

```bash
# Format: <type>(<scope>): <subject>
# Types: feat, fix, docs, style, refactor, test, chore

git add .
git commit -m "feat(router): add dynamic threshold adjustment"

# Examples:
# feat(moe): add support for custom replacement tokens
# fix(chunking): handle empty input gracefully
# docs(readme): update installation instructions
# test(filters): add test for JWT detection
# refactor(features): simplify entropy calculation
```

### 4. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
# Fill out the PR template
```

### 5. PR Review Process

1. **Automated checks**: CI will run tests, linting, and type checking
2. **Code review**: Maintainers will review your code
3. **Address feedback**: Make requested changes
4. **Approval**: Once approved, your PR will be merged

### PR Checklist

Before submitting a PR, ensure:

- [ ] Code follows style guidelines (Black, flake8, mypy)
- [ ] All tests pass (`pytest`)
- [ ] New code has tests (>80% coverage)
- [ ] Documentation updated (docstrings, README, etc.)
- [ ] Commit messages follow conventional format
- [ ] PR description clearly explains changes
- [ ] No merge conflicts with `main`
- [ ] Changes are atomic (one feature/fix per PR)

---

## Areas for Contribution

### 🔥 High Priority

1. **Performance Optimization**

   - ONNX conversion for faster inference
   - Quantization to reduce model size
   - Batch processing improvements

2. **New Secret Types**

   - Support for additional secret formats
   - Domain-specific secrets (MongoDB, Redis, etc.)
   - Custom secret patterns

3. **Router Improvements**

   - Dynamic threshold adjustment
   - Multi-class routing (fast/medium/long)
   - Confidence calibration

4. **Documentation**
   - More use case examples
   - Video tutorials
   - Translation to other languages

### 🌟 Feature Ideas

1. **CLI Enhancements**

   - Interactive mode
   - JSON output format
   - Progress bars for batch processing

2. **API Server**

   - REST API with FastAPI
   - gRPC support
   - WebSocket streaming

3. **Integrations**

   - GitHub Action
   - VS Code extension
   - GitLab CI/CD template
   - Jenkins plugin

4. **Training Improvements**

   - Active learning pipeline
   - Data augmentation
   - Multi-language support

5. **Deployment**
   - Helm chart for Kubernetes
   - Terraform modules
   - AWS CDK construct

### 🐛 Bug Reports

**Found a bug? Please open an issue with:**

- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Code snippet or logs

**Example:**

```markdown
### Bug: False positive on hex color codes

**Description:** SecMask incorrectly masks hex color codes like `#1a2b3c`.

**Steps to Reproduce:**

1. Run: `python infer_moe.py --in colors.txt --fast-model andrewandrewsen/distilbert-secret-masker`
2. Input: `background-color: #1a2b3c;`
3. Output: `background-color: [SECRET];`

**Expected:** Color code should not be masked.

**Environment:**

- OS: macOS 13.0
- Python: 3.11.5
- transformers: 4.36.0
```

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors.

### Expected Behavior

- Be respectful and professional
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what's best for the project

### Unacceptable Behavior

- Harassment or discrimination
- Trolling or insulting comments
- Personal attacks
- Publishing others' private information

### Enforcement

Violations may result in:

1. Warning
2. Temporary ban
3. Permanent ban

Report issues to: [your-email@example.com]

---

## Questions and Support

### Getting Help

1. **Documentation**: Check [README.md](README.md) and other docs
2. **Examples**: See [EXAMPLES.md](EXAMPLES.md)
3. **Issues**: Search [existing issues](https://github.com/andrewandrewsen/secmask/issues)
4. **Discussions**: Ask in [GitHub Discussions](https://github.com/andrewandrewsen/secmask/discussions)

### Contact

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Email**: [your-email@example.com]
- **Twitter**: [@yourhandle]

---

## Development Workflow Example

**Complete workflow for adding a new feature:**

```bash
# 1. Set up development environment
git clone https://github.com/YOUR_USERNAME/secmask.git
cd secmask
conda create -n secmask-dev python=3.11 -y
conda activate secmask-dev
pip install -r requirements.txt
pip install pytest black flake8 mypy

# 2. Create feature branch
git checkout -b feat/custom-replacement-token

# 3. Implement feature
# Edit infer_moe.py to add replacement_token parameter
# ...

# 4. Write tests
# Create tests/test_custom_token.py
# ...

# 5. Format and lint
black .
flake8 --max-line-length=100
mypy --ignore-missing-imports .

# 6. Run tests
pytest

# 7. Commit changes
git add .
git commit -m "feat(moe): add custom replacement token parameter"

# 8. Push and create PR
git push origin feat/custom-replacement-token
# Open PR on GitHub

# 9. Address review feedback
# Make changes based on code review
git add .
git commit -m "fix: address PR feedback"
git push origin feat/custom-replacement-token

# 10. Merge!
# Maintainer will merge your PR
```

---

## Recognition

Contributors will be:

- Listed in [CONTRIBUTORS.md](CONTRIBUTORS.md)
- Mentioned in release notes
- Acknowledged in the README

Thank you for contributing to SecMask! 🎉

---

**License:** By contributing, you agree that your contributions will be licensed under the MIT License.

# AGENTS.md - Agentic Coding Guidelines

This file provides guidelines for agentic coding agents working in this repository.

## Project Overview

This is a **LangGraph-based Multi-Agent Vulnerability Data Processing System** written in Python. It processes vulnerability data from 6 sources (CVE, NVD, CNVD, CISA, CERT, JVN) using LangGraph state machine with 3 core nodes: Extractor, Cleaner-Validator, and Storage.

## Build/Lint/Test Commands

### Running the System

```bash
# Process a single file
python main.py --file html/cnvd/2024/CNVD-2024-12345.html

# Process a directory
python main.py --directory html/cnvd/2024/

# With custom workers
python main.py --directory html/ --workers 8
```

### Running Tests

```bash
# Run all tests
python tests/test_langgraph.py

# Or use pytest
pytest tests/
```

### Linting

```bash
# Fast linting
ruff check .

# Type checking
mypy .
```

## Code Style Guidelines

### General Principles

- Use **Python 3.9+** features (type hints, async/await)
- Keep functions focused and small (< 100 lines preferred)
- Use **logging** for runtime messages, not print (except final stats output)
- All file operations must use `encoding='utf-8'`

### Imports

```python
# Standard library first
import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Any

# Third-party libraries
import yaml
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END

# Local application imports
from graph.state import VulnProcessingState
from graph.nodes import extract_node, clean_validate_node
from agents.extractor import ExtractorAgent
from database.manager import DatabaseManager
```

### Type Hints

Always use type hints for function signatures:

```python
def process_file(self, file_path: str) -> Dict[str, Any]:
    """Process a single file.
    
    Args:
        file_path: Path to the file to process.
        
    Returns:
        Processing result dictionary.
    """
    ...

async def extract_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    ...
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `ExtractorAgent`, `DatabaseManager`)
- **Functions/variables**: `snake_case` (e.g., `extract_node`, `config_path`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_LLM_MODEL`, `MAX_RETRIES`)
- **Private methods**: `_leading_underscore` (e.g., `_apply_rule`)

### Docstrings

Use Google-style docstrings:

```python
def function_name(param1: Type1, param2: Type2) -> ReturnType:
    """Short description of what the function does.

    Longer description if needed, explaining the behavior
    and any important implementation details.

    Args:
        param1: Description of param1.
        param2: Description of param2.

    Returns:
        Description of what is returned.

    Raises:
        ValueError: When this condition occurs.
        IOError: When file operations fail.
    """
```

### Error Handling

```python
try:
    result = risky_operation()
except SpecificException as e:
    logger.error(f"Operation failed: {e}")
    return None
except Exception as e:
    logger.error(f"Unexpected error: {e}", exc_info=True)
    raise
```

- Always log errors with appropriate level
- Use `exc_info=True` for unexpected errors in logging
- Return `None` or empty collections for expected failure cases
- Raise custom exceptions for unexpected failures

### Configuration

- All configuration in YAML files under `config/`
- Environment variables in `.env` file (never commit this)
- Use the config loaders: `FieldConfigLoader`, `EnvConfigLoader`

### File Paths

```python
# Use pathlib for file operations
from pathlib import Path

# Good
config_path = Path(__file__).parent / 'config' / 'agent_config.yaml'

# Bad
config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'agent_config.yaml')
```

### Async/Await Patterns

The controller uses asyncio for concurrent processing:

```python
async def process_file(self, file_path: str) -> Dict[str, Any]:
    initial_state = create_initial_state(task_id, file_path)
    final_state = await self.graph.ainvoke(initial_state)
    return final_state

# Concurrent processing
semaphore = asyncio.Semaphore(max_workers)
async def process_with_limit(file_path: Path):
    async with semaphore:
        return await self.process_file(str(file_path))

results = await asyncio.gather(*[process_with_limit(f) for f in files])
```

### Database Operations

- Use SQLAlchemy ORM with batch operations
- Always use parameterized queries
- Implement upsert logic for deduplication

### Logging

```python
import logging

logger = logging.getLogger(__name__)

# Use appropriate levels
logger.debug("Detailed debug info")
logger.info("Normal operation info")
logger.warning("Something unexpected but handled")
logger.error("Operation failed", exc_info=True)
```

### Code Organization

```
.
├── main.py                 # Entry point
├── graph/                  # LangGraph implementation
│   ├── __init__.py
│   ├── state.py           # State definition
│   ├── nodes.py           # Node functions
│   ├── builder.py         # Graph builder
│   └── controller.py      # Controller
├── agents/                # Agent implementations
│   ├── extractor.py
│   ├── cleaner_validator.py
│   └── storage.py
├── config/                # Configuration
│   ├── agent_config.yaml
│   ├── field_mappings.yaml
│   └── field_config_loader.py
├── database/              # Database layer
│   ├── manager.py
│   └── process_tracker.py
└── tests/                 # Tests
    └── test_langgraph.py
```

### YAML Configuration Format

```yaml
agents:
  extractor:
    enabled: true
    timeout: 30
  cleaner_validator:
    enabled: true
    quality_threshold: 0.7
  storage:
    enabled: true
    batch_size: 50

processing:
  max_workers: 4
  timeout: 3600
```

### Testing Guidelines

When adding tests:
- Create test functions in `tests/` directory
- Use descriptive test names: `test_<module>_<functionality>`
- Test both success and failure paths
- Use assertions with descriptive messages

```python
async def test_single_file():
    """Test single file processing."""
    try:
        controller = LangGraphController(config)
        result = await controller.process_file(test_file)
        assert result['final_status'] in ['success', 'low_quality']
        logger.info("✓ Test passed")
        return True
    except Exception as e:
        logger.error(f"✗ Test failed: {e}")
        return False
```

### LangGraph Patterns

**Node function:**
```python
def extract_node(state: VulnProcessingState, config: Dict) -> VulnProcessingState:
    """Extract node - extracts vulnerability data from files."""
    try:
        # Processing logic
        return {
            **state,
            'extracted_data': data,
            'extraction_confidence': confidence
        }
    except Exception as e:
        logger.error(f"Extraction failed: {e}", exc_info=True)
        return {
            **state,
            'errors': state.get('errors', []) + [str(e)],
            'final_status': 'failed'
        }
```

**Conditional routing:**
```python
def check_quality(state: VulnProcessingState, config: Dict) -> str:
    """Check data quality and route accordingly."""
    threshold = config.get('agents', {}).get('cleaner_validator', {}).get('quality_threshold', 0.7)
    if state['quality_score'] >= threshold:
        return "store"
    else:
        return "low_quality"
```

**Graph building:**
```python
from langgraph.graph import StateGraph, END
from functools import partial

workflow = StateGraph(VulnProcessingState)

# Bind config to nodes
extract_with_config = partial(extract_node, config=config)
clean_with_config = partial(clean_validate_node, config=config)

# Add nodes
workflow.add_node("extract", extract_with_config)
workflow.add_node("clean", clean_with_config)

# Add edges
workflow.set_entry_point("extract")
workflow.add_edge("extract", "clean")
workflow.add_conditional_edges("clean", check_quality, {...})
workflow.add_edge("store", END)

graph = workflow.compile()
```

## Environment Setup

Create a `.env` file in the project root:

```bash
OPENAI_API_KEY=your_api_key_here
OPENAI_API_BASE=http://localhost:8000/v1
DEFAULT_LLM_MODEL=gpt-4o-mini
DB_URI=mysql+pymysql://user:password@localhost/vuln_db
```

## Key Files Reference

| File | Purpose |
|------|---------|
| `main.py` | CLI entry point, argument parsing |
| `graph/controller.py` | LangGraph controller |
| `graph/builder.py` | Graph builder |
| `graph/nodes.py` | Node functions |
| `graph/state.py` | State definition |
| `agents/extractor.py` | Extracts data from HTML/JSON |
| `agents/cleaner_validator.py` | Validates and cleans data |
| `agents/storage.py` | Database persistence |
| `database/manager.py` | SQLAlchemy ORM layer |
| `config/field_mappings.yaml` | Source-specific extraction rules |

## Performance Considerations

- Default workers: 4 (match CPU cores)
- Batch insert size: 50 records
- HTML content truncation: 8000 chars for LLM
- Use asyncio for concurrent processing (lower memory footprint than threads)
- Quality threshold: 0.7 (filter low-quality data)

## Architecture Benefits

### LangGraph vs Thread-based

| Aspect | Thread-based | LangGraph |
|--------|-------------|-----------|
| Code lines | ~320 lines | ~100 lines |
| Concurrency | Threads | Asyncio |
| Memory | Medium | Low |
| Scalability | Limited | High |
| Observability | Manual | Built-in |
| Error handling | Manual | Automatic |

### Graph Structure

```
START → extract → clean → [quality_check] → store → END
                              ↓
                         low_quality → END
```

- **extract**: Read file, identify source, extract data
- **clean**: Clean strings, validate fields, calculate quality score
- **quality_check**: Route based on quality score
- **store**: Persist to database
- **low_quality**: Mark low-quality data

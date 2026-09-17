"""Cold-start bootstrap and seed fixtures for local offline operation.
Implements Section 1.3.5 (deps.dev, OSV bulk exports, offline seed data).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from monarch.common.storage import Storage
from monarch.ingestion.cas import ContentAddressedStorage
from monarch.ingestion.hydrator import Hydrator

# Realistic ecosystem sample including core packages and historic incident cases
SAMPLE_PACKAGES: List[Dict[str, Any]] = [
    {
        "name": "chalk",
        "description": "Terminal string styling done right",
        "maintainers": [{"name": "sindresorhus", "email": "sindre@example.com"}],
        "time": {
            "4.1.0": "2020-04-10T12:00:00Z",
            "4.1.2": "2021-08-01T12:00:00Z",
        },
        "versions": {
            "4.1.0": {
                "name": "chalk",
                "version": "4.1.0",
                "_npmUser": {"name": "sindresorhus", "email": "sindre@example.com"},
                "dependencies": {"ansi-styles": "^4.1.0", "supports-color": "^7.1.0"},
                "dist": {"unpackedSize": 31000, "fileCount": 7, "attestations": True},
            },
            "4.1.2": {
                "name": "chalk",
                "version": "4.1.2",
                "_npmUser": {"name": "sindresorhus", "email": "sindre@example.com"},
                "dependencies": {"ansi-styles": "^4.1.0", "supports-color": "^7.1.0"},
                "dist": {"unpackedSize": 32000, "fileCount": 7, "attestations": True},
            },
        },
    },
    {
        "name": "ansi-styles",
        "description": "ANSI escape codes for styling strings in the terminal",
        "maintainers": [{"name": "sindresorhus", "email": "sindre@example.com"}],
        "time": {
            "4.3.0": "2020-05-15T12:00:00Z",
        },
        "versions": {
            "4.3.0": {
                "name": "ansi-styles",
                "version": "4.3.0",
                "_npmUser": {"name": "sindresorhus", "email": "sindre@example.com"},
                "dependencies": {"color-convert": "^2.0.1"},
                "dist": {"unpackedSize": 15000, "fileCount": 5, "attestations": True},
            }
        },
    },
    {
        "name": "color-convert",
        "maintainers": [{"name": "qix", "email": "qix@example.com"}],
        "time": {
            "2.0.1": "2019-06-01T12:00:00Z",
        },
        "versions": {
            "2.0.1": {
                "name": "color-convert",
                "version": "2.0.1",
                "_npmUser": {"name": "qix", "email": "qix@example.com"},
                "dependencies": {"color-name": "~1.1.4"},
                "dist": {"unpackedSize": 27000, "fileCount": 8},
            }
        },
    },
    {
        "name": "color-name",
        "maintainers": [{"name": "dfcreative", "email": "df@example.com"}],
        "time": {
            "1.1.4": "2018-02-01T12:00:00Z",
        },
        "versions": {
            "1.1.4": {
                "name": "color-name",
                "version": "1.1.4",
                "_npmUser": {"name": "dfcreative", "email": "df@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 5000, "fileCount": 3},
            }
        },
    },
    {
        "name": "supports-color",
        "maintainers": [{"name": "sindresorhus", "email": "sindre@example.com"}],
        "time": {
            "7.2.0": "2020-09-01T12:00:00Z",
        },
        "versions": {
            "7.2.0": {
                "name": "supports-color",
                "version": "7.2.0",
                "_npmUser": {"name": "sindresorhus", "email": "sindre@example.com"},
                "dependencies": {"has-flag": "^4.0.0"},
                "dist": {"unpackedSize": 8000, "fileCount": 4},
            }
        },
    },
    {
        "name": "has-flag",
        "maintainers": [{"name": "sindresorhus", "email": "sindre@example.com"}],
        "time": {
            "4.0.0": "2019-04-01T12:00:00Z",
        },
        "versions": {
            "4.0.0": {
                "name": "has-flag",
                "version": "4.0.0",
                "_npmUser": {"name": "sindresorhus", "email": "sindre@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 4000, "fileCount": 3},
            }
        },
    },
    {
        "name": "express",
        "description": "Fast, unopinionated, minimalist web framework",
        "maintainers": [{"name": "dougwilson", "email": "doug@example.com"}],
        "time": {
            "4.18.2": "2022-10-08T12:00:00Z",
        },
        "versions": {
            "4.18.2": {
                "name": "express",
                "version": "4.18.2",
                "_npmUser": {"name": "dougwilson", "email": "doug@example.com"},
                "dependencies": {
                    "accepts": "~1.3.8",
                    "body-parser": "1.20.1",
                    "chalk": "^4.1.0",
                },
                "dist": {"unpackedSize": 210000, "fileCount": 30},
            }
        },
    },
    {
        "name": "accepts",
        "maintainers": [{"name": "dougwilson", "email": "doug@example.com"}],
        "time": {"1.3.8": "2022-01-20T12:00:00Z"},
        "versions": {
            "1.3.8": {
                "name": "accepts",
                "version": "1.3.8",
                "dependencies": {},
                "dist": {"unpackedSize": 18000, "fileCount": 5},
            }
        },
    },
    {
        "name": "body-parser",
        "maintainers": [{"name": "dougwilson", "email": "doug@example.com"}],
        "time": {"1.20.1": "2022-10-01T12:00:00Z"},
        "versions": {
            "1.20.1": {
                "name": "body-parser",
                "version": "1.20.1",
                "dependencies": {},
                "dist": {"unpackedSize": 48000, "fileCount": 12},
            }
        },
    },
    {
        "name": "api-gateway",
        "maintainers": [{"name": "enterprise-org", "email": "dev@corp.com"}],
        "time": {"2.0.0": "2023-01-01T12:00:00Z"},
        "versions": {
            "2.0.0": {
                "name": "api-gateway",
                "version": "2.0.0",
                "dependencies": {"express": "^4.18.0"},
                "dist": {"unpackedSize": 50000, "fileCount": 10},
            }
        },
    },
    {
        "name": "web-dashboard",
        "maintainers": [{"name": "dashboard-team", "email": "team@dash.io"}],
        "time": {"1.5.0": "2023-02-01T12:00:00Z"},
        "versions": {
            "1.5.0": {
                "name": "web-dashboard",
                "version": "1.5.0",
                "dependencies": {"express": "4.18.2", "chalk": "^4.1.0"},
                "dist": {"unpackedSize": 85000, "fileCount": 15},
            }
        },
    },
    {
        "name": "auth-service",
        "maintainers": [{"name": "sec-team", "email": "sec@corp.com"}],
        "time": {"3.1.0": "2023-03-01T12:00:00Z"},
        "versions": {
            "3.1.0": {
                "name": "auth-service",
                "version": "3.1.0",
                "dependencies": {"express": "^4.17.0"},
                "dist": {"unpackedSize": 40000, "fileCount": 8},
            }
        },
    },
    {
        "name": "payment-api",
        "maintainers": [{"name": "pay-team", "email": "pay@corp.com"}],
        "time": {"1.0.0": "2023-04-01T12:00:00Z"},
        "versions": {
            "1.0.0": {
                "name": "payment-api",
                "version": "1.0.0",
                "dependencies": {"api-gateway": "^2.0.0"},
                "dist": {"unpackedSize": 60000, "fileCount": 12},
            }
        },
    },
    {
        "name": "admin-portal",
        "maintainers": [{"name": "admin-team", "email": "admin@corp.com"}],
        "time": {"1.2.0": "2023-05-01T12:00:00Z"},
        "versions": {
            "1.2.0": {
                "name": "admin-portal",
                "version": "1.2.0",
                "dependencies": {"web-dashboard": "^1.5.0"},
                "dist": {"unpackedSize": 75000, "fileCount": 14},
            }
        },
    },
    # Incident Case: event-stream (2018 handover after dormancy + malicious flatmap-stream)
    {
        "name": "event-stream",
        "maintainers": [
            {"name": "dominictarr", "email": "dominic@example.com"},
            {"name": "right9ctrl", "email": "right9ctrl@example.com"},
        ],
        "time": {
            "3.3.4": "2016-01-10T12:00:00Z",
            "3.3.5": "2018-09-05T12:00:00Z",
            "3.3.6": "2018-09-10T12:00:00Z",
        },
        "versions": {
            "3.3.4": {
                "name": "event-stream",
                "version": "3.3.4",
                "_npmUser": {"name": "dominictarr", "email": "dominic@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 28000, "fileCount": 10},
            },
            "3.3.5": {
                "name": "event-stream",
                "version": "3.3.5",
                "_npmUser": {"name": "right9ctrl", "email": "right9ctrl@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 29000, "fileCount": 10},
            },
            "3.3.6": {
                "name": "event-stream",
                "version": "3.3.6",
                "_npmUser": {"name": "right9ctrl", "email": "right9ctrl@example.com"},
                "dependencies": {"flatmap-stream": "0.1.1"},
                "dist": {"unpackedSize": 30000, "fileCount": 10},
            },
        },
    },
    {
        "name": "flatmap-stream",
        "maintainers": [{"name": "right9ctrl", "email": "right9ctrl@example.com"}],
        "time": {"0.1.1": "2018-09-09T12:00:00Z"},
        "versions": {
            "0.1.1": {
                "name": "flatmap-stream",
                "version": "0.1.1",
                "_npmUser": {"name": "right9ctrl", "email": "right9ctrl@example.com"},
                "scripts": {"preinstall": "node test/data.js"},
                "dependencies": {},
                "dist": {"unpackedSize": 65000, "fileCount": 4},
            }
        },
    },
    # Incident Case: xz-utils (simulated npm model for CVE-2024-3094 repo drift)
    {
        "name": "xz-utils-embedded",
        "maintainers": [
            {"name": "larhpa", "email": "lasse@example.com"},
            {"name": "jia-tan", "email": "jiatan@example.com"},
        ],
        "time": {
            "5.4.0": "2022-12-01T12:00:00Z",
            "5.6.0": "2024-02-24T12:00:00Z",
            "5.6.1": "2024-03-09T12:00:00Z",
        },
        "versions": {
            "5.4.0": {
                "name": "xz-utils-embedded",
                "version": "5.4.0",
                "_npmUser": {"name": "larhpa", "email": "lasse@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 1200000, "fileCount": 150},
            },
            "5.6.0": {
                "name": "xz-utils-embedded",
                "version": "5.6.0",
                "_npmUser": {"name": "jia-tan", "email": "jiatan@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 1800000, "fileCount": 165},
            },
            "5.6.1": {
                "name": "xz-utils-embedded",
                "version": "5.6.1",
                "_npmUser": {"name": "jia-tan", "email": "jiatan@example.com"},
                "dependencies": {},
                "dist": {"unpackedSize": 1850000, "fileCount": 165},
            },
        },
    },
]


def bootstrap_database(storage: Storage, cas: ContentAddressedStorage) -> int:
    """Load the reference offline bootstrap corpus into storage."""
    hydrator = Hydrator(storage, cas)
    count = 0
    for pkg_dict in SAMPLE_PACKAGES:
        hydrator.hydrate_packument_json(pkg_dict)
        count += 1
    return count

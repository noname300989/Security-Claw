---
name: job-hunter-automation
description: "Automated security job hunting via the job-hunter-automation hook. Browses job portals (LinkedIn, Indeed, company career pages) daily for Penetration Testing and Application Security roles, saves matching postings, and requests browser sign-ins as needed. Triggered by cron:daily."
metadata: { "openclaw": { "emoji": "🎯" } }
---

# Job Hunter Automation Hook

Automated daily browsing of job portals for security roles.

## When to Use

✅ **USE this skill when:**

- Setting up automated daily job search for security roles
- Searching for new Penetration Testing or AppSec postings
- Reviewing today's discovered job listings
- Customizing the search terms or target portals

## How It Works

The `job-hunter-automation` hook fires on `cron:daily` and:

1. Opens job portals in the browser (LinkedIn, Indeed, company career pages)
2. Searches for configured job titles (Penetration Tester, AppSec Engineer, Red Team, etc.)
3. Saves matching postings to a local file
4. Notifies via messaging channels if sign-in is required
5. Sends a summary of new listings to all channels

## Trigger On-Demand

```json
{ "tool": "cron", "action": "run", "jobId": "job-hunter-automation" }
```

Or ask the agent:

```
Search job boards for new penetration testing roles today
Find new security jobs posted this week on LinkedIn and Indeed
```

## Target Roles

Default search terms:

- Penetration Tester / Pen Tester
- Application Security Engineer
- Red Team Operator
- Security Researcher
- Bug Bounty Hunter
- Offensive Security Engineer

## Customize Search

Ask the agent to adjust the search:

```
Search for "OSCP required" security jobs in the USA posted this week
Look for remote red team roles on LinkedIn and save the results
Search for cloud security and DFIR roles, skip junior positions
```

## Results Format

Discovered jobs are saved to `jobs/YYYY-MM-DD.json`:

```json
{
  "date": "2026-02-23",
  "jobs": [
    {
      "title": "Senior Penetration Tester",
      "company": "ACME Corp",
      "location": "Remote",
      "url": "https://linkedin.com/jobs/view/...",
      "posted": "2026-02-22",
      "matchScore": 0.92
    }
  ]
}
```

## Config

```json5
{
  cron: {
    jobs: [
      {
        id: "job-hunter-automation",
        schedule: "0 8 * * 1-5",
        task: "Browse job portals for new penetration testing and security roles",
      },
    ],
  },
}
```

## Usage from Agent

```
Run the job hunter now and find new security jobs posted today
Search LinkedIn and Indeed for red team operator roles posted this week
Show me the jobs discovered in today's automated run
Update the job search to include cloud security and DevSecOps roles
```

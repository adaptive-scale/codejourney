use chrono::{DateTime, Datelike, NaiveDateTime, Timelike, Utc};
use git2::{DiffOptions, Repository, Sort, Time};
use std::collections::HashMap;

use crate::display;

fn git_time_to_naive(time: Time) -> Option<NaiveDateTime> {
    DateTime::<Utc>::from_timestamp(time.seconds(), 0).map(|dt| dt.naive_utc())
}

fn one_year_ago() -> i64 {
    chrono::Utc::now().timestamp() - 365 * 24 * 3600
}

/// Most frequently changed files in the last year
pub fn most_changed_files(repo: &Repository, limit: usize) -> Result<(), git2::Error> {
    display::print_sub_header("Most Frequently Changed Files (1 year)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let cutoff = one_year_ago();
    let mut file_counts: HashMap<String, usize> = HashMap::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if commit.time().seconds() < cutoff {
            break;
        }

        let tree = commit.tree()?;
        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let mut diff_opts = DiffOptions::new();
        let diff = repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&tree),
            Some(&mut diff_opts),
        )?;

        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    let p = path.to_string_lossy().to_string();
                    *file_counts.entry(p).or_insert(0) += 1;
                }
                true
            },
            None,
            None,
            None,
        )?;
    }

    let mut sorted: Vec<_> = file_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(limit);

    let items: Vec<(String, usize)> = sorted;
    display::print_bar_chart(&items, "\x1b[34m");

    Ok(())
}

/// Top contributors by commit count
pub fn top_contributors(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Top Contributors (by commits, no merges)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut author_counts: HashMap<String, usize> = HashMap::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if commit.parent_count() > 1 {
            continue; // skip merges
        }
        let name = commit
            .author()
            .name()
            .unwrap_or("unknown")
            .to_string();
        *author_counts.entry(name).or_insert(0) += 1;
    }

    let mut sorted: Vec<_> = author_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(20);

    display::print_bar_chart(&sorted, "\x1b[32m");

    Ok(())
}

/// Files most associated with bug fixes
pub fn bug_fix_files(repo: &Repository, limit: usize) -> Result<(), git2::Error> {
    display::print_sub_header("Files Most Associated with Bug Fixes");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let pattern = regex::Regex::new(r"(?i)(fix|bug|broken)").unwrap();
    let mut file_counts: HashMap<String, usize> = HashMap::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let msg = commit.message().unwrap_or("");
        if !pattern.is_match(msg) {
            continue;
        }

        let tree = commit.tree()?;
        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let mut diff_opts = DiffOptions::new();
        let diff =
            repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_opts))?;

        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    let p = path.to_string_lossy().to_string();
                    *file_counts.entry(p).or_insert(0) += 1;
                }
                true
            },
            None,
            None,
            None,
        )?;
    }

    let mut sorted: Vec<_> = file_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(limit);

    display::print_bar_chart(&sorted, "\x1b[31m");

    Ok(())
}

/// Commit frequency by month
pub fn commit_frequency_by_month(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Commit Frequency by Month");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut month_counts: HashMap<String, usize> = HashMap::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if let Some(dt) = git_time_to_naive(commit.time()) {
            let key = format!("{}-{:02}", dt.year(), dt.month());
            *month_counts.entry(key).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = month_counts.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    // Show sparkline for recent months, then bar chart
    if sorted.len() > 12 {
        let recent = &sorted[sorted.len() - 12..];
        display::print_sparkline(recent);
        println!();
    }

    // Show last 24 months max
    if sorted.len() > 24 {
        sorted = sorted[sorted.len() - 24..].to_vec();
    }
    display::print_bar_chart(&sorted, "\x1b[35m");

    Ok(())
}

/// Reverts, hotfixes, emergency commits
pub fn emergency_commits(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Reverts / Hotfixes / Emergency Commits (1 year)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let cutoff = one_year_ago();
    let pattern = regex::Regex::new(r"(?i)(revert|hotfix|emergency|rollback)").unwrap();
    let mut entries: Vec<(String, String)> = Vec::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if commit.time().seconds() < cutoff {
            break;
        }
        let msg = commit.message().unwrap_or("").trim().to_string();
        if pattern.is_match(&msg) {
            let short_hash = oid.to_string()[..7].to_string();
            entries.push((short_hash, msg));
        }
    }

    if entries.is_empty() {
        display::print_ok("No revert/hotfix/emergency commits found in the last year");
    } else {
        display::print_warning(&format!("Found {} emergency-type commits:", entries.len()));
        let rows: Vec<Vec<String>> = entries
            .iter()
            .map(|(h, m)| {
                let truncated = if m.len() > 60 {
                    format!("{}…", &m[..59])
                } else {
                    m.clone()
                };
                vec![h.clone(), truncated]
            })
            .collect();
        display::print_table(&["Hash", "Message"], &rows);
    }

    Ok(())
}

/// Code churn: most frequently changed files (last 500 commits)
pub fn code_churn(repo: &Repository, limit: usize) -> Result<(), git2::Error> {
    display::print_sub_header("Code Churn (top files in last 500 commits)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut file_counts: HashMap<String, usize> = HashMap::new();
    let mut count = 0;

    for oid in revwalk {
        if count >= 500 {
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let tree = commit.tree()?;
        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let mut diff_opts = DiffOptions::new();
        let diff =
            repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_opts))?;

        diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    let p = path.to_string_lossy().to_string();
                    *file_counts.entry(p).or_insert(0) += 1;
                }
                true
            },
            None,
            None,
            None,
        )?;

        count += 1;
    }

    let mut sorted: Vec<_> = file_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(limit);

    display::print_bar_chart(&sorted, "\x1b[33m");

    Ok(())
}

/// Average commits per day (last year)
pub fn commits_per_day(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Commit Velocity");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let cutoff = one_year_ago();
    let mut total = 0usize;

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if commit.time().seconds() < cutoff {
            break;
        }
        total += 1;
    }

    let avg = total as f64 / 365.0;
    display::print_summary_stat("Total commits (last year)", &total.to_string());
    display::print_summary_stat("Average per day", &format!("{avg:.1}"));
    display::print_summary_stat("Average per week", &format!("{:.1}", avg * 7.0));

    Ok(())
}

/// Lines added/removed per author (last year, capped at 1000 commits for performance)
pub fn lines_per_author(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Lines Added/Removed per Author (1 year, up to 1000 commits)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let cutoff = one_year_ago();
    let mut author_stats: HashMap<String, (usize, usize)> = HashMap::new();
    let mut processed = 0usize;
    let max_commits = 1000;

    for oid in revwalk {
        if processed >= max_commits {
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if commit.time().seconds() < cutoff {
            break;
        }
        if commit.parent_count() > 1 {
            continue; // skip merges
        }

        let name = commit
            .author()
            .name()
            .unwrap_or("unknown")
            .to_string();
        let tree = commit.tree()?;
        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let mut diff_opts = DiffOptions::new();
        let diff =
            repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut diff_opts))?;

        let stats = diff.stats()?;
        let entry = author_stats.entry(name).or_insert((0, 0));
        entry.0 += stats.insertions();
        entry.1 += stats.deletions();
        processed += 1;
    }

    let mut sorted: Vec<_> = author_stats.into_iter().collect();
    sorted.sort_by(|a, b| (b.1 .0 + b.1 .1).cmp(&(a.1 .0 + a.1 .1)));
    sorted.truncate(20);

    let rows: Vec<Vec<String>> = sorted
        .iter()
        .map(|(name, (add, del))| {
            vec![
                name.clone(),
                format!("\x1b[32m+{add}\x1b[0m"),
                format!("\x1b[31m-{del}\x1b[0m"),
                format!("{}", add + del),
            ]
        })
        .collect();
    display::print_table(&["Author", "Added", "Removed", "Total"], &rows);

    Ok(())
}

/// Commit activity by day of week
pub fn activity_by_day_of_week(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Commit Activity by Day of Week");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let mut day_counts: [usize; 7] = [0; 7];

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if let Some(dt) = git_time_to_naive(commit.time()) {
            let weekday = dt.weekday().num_days_from_monday() as usize;
            day_counts[weekday] += 1;
        }
    }

    let items: Vec<(String, usize)> = days
        .iter()
        .enumerate()
        .map(|(i, d)| (d.to_string(), day_counts[i]))
        .collect();
    display::print_bar_chart(&items, "\x1b[36m");

    Ok(())
}

/// Commit activity by hour
pub fn activity_by_hour(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Commit Activity by Hour of Day");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut hour_counts: [usize; 24] = [0; 24];

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let offset_minutes = commit.time().offset_minutes();
        if let Some(dt) = git_time_to_naive(commit.time()) {
            // Adjust for timezone offset
            let adjusted = dt + chrono::Duration::minutes(offset_minutes as i64);
            hour_counts[adjusted.hour() as usize] += 1;
        }
    }

    let items: Vec<(String, usize)> = (0..24)
        .map(|h| (format!("{h:02}:00"), hour_counts[h]))
        .collect();
    display::print_bar_chart(&items, "\x1b[35m");

    Ok(())
}

/// Merge frequency by month
pub fn merge_frequency(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Merge Frequency by Month (1 year)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let cutoff = one_year_ago();
    let mut month_counts: HashMap<String, usize> = HashMap::new();

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        if commit.time().seconds() < cutoff {
            break;
        }
        if commit.parent_count() <= 1 {
            continue; // only merges
        }
        if let Some(dt) = git_time_to_naive(commit.time()) {
            let key = format!("{}-{:02}", dt.year(), dt.month());
            *month_counts.entry(key).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = month_counts.into_iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    if sorted.is_empty() {
        display::print_info("No merge commits found in the last year");
    } else {
        display::print_bar_chart(&sorted, "\x1b[34m");
    }

    Ok(())
}

/// First and last commit dates, total commits, branches
pub fn repo_overview(repo: &Repository) -> Result<(), git2::Error> {
    display::print_sub_header("Repository Overview");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    let mut first_date: Option<NaiveDateTime> = None;
    let mut last_date: Option<NaiveDateTime> = None;
    let mut total_commits = 0usize;

    for oid in revwalk {
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let dt = git_time_to_naive(commit.time());

        if last_date.is_none() {
            last_date = dt;
        }
        first_date = dt;
        total_commits += 1;
    }

    // Count branches
    let branches = repo.branches(Some(git2::BranchType::Local))?;
    let branch_count = branches.count();

    // Count tags
    let tag_names = repo.tag_names(None)?;
    let tag_count = tag_names.len();

    display::print_summary_stat("Total commits", &total_commits.to_string());
    display::print_summary_stat("Branches", &branch_count.to_string());
    display::print_summary_stat("Tags", &tag_count.to_string());

    if let Some(first) = first_date {
        display::print_summary_stat("First commit", &first.format("%Y-%m-%d %H:%M").to_string());
    }
    if let Some(last) = last_date {
        display::print_summary_stat("Last commit", &last.format("%Y-%m-%d %H:%M").to_string());
    }

    if let (Some(first), Some(last)) = (first_date, last_date) {
        let days = (last - first).num_days();
        display::print_summary_stat("Active span", &format!("{days} days"));
    }

    Ok(())
}

/// Largest files currently tracked
pub fn largest_tracked_files(repo: &Repository, limit: usize) -> Result<(), git2::Error> {
    display::print_sub_header("Largest Tracked Files");

    let head = repo.head()?.peel_to_tree()?;
    let mut file_sizes: Vec<(String, usize)> = Vec::new();

    head.walk(git2::TreeWalkMode::PreOrder, |dir, entry| {
        if entry.kind() == Some(git2::ObjectType::Blob) {
            let path = format!("{}{}", dir, entry.name().unwrap_or(""));
            if let Ok(blob) = repo.find_blob(entry.id()) {
                file_sizes.push((path, blob.size()));
            }
        }
        git2::TreeWalkResult::Ok
    })?;

    file_sizes.sort_by(|a, b| b.1.cmp(&a.1));
    file_sizes.truncate(limit);

    let rows: Vec<Vec<String>> = file_sizes
        .iter()
        .map(|(path, size)| {
            let human = if *size > 1_048_576 {
                format!("{:.1} MB", *size as f64 / 1_048_576.0)
            } else if *size > 1024 {
                format!("{:.1} KB", *size as f64 / 1024.0)
            } else {
                format!("{size} B")
            };
            vec![path.clone(), human]
        })
        .collect();
    display::print_table(&["File", "Size"], &rows);

    Ok(())
}

/// Stale files: single-pass through last 1000 commits to find last-modified date per file
pub fn stale_files(repo: &Repository, limit: usize) -> Result<(), git2::Error> {
    display::print_sub_header("Stale Files (oldest by last modification)");

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(Sort::TIME)?;

    // Single pass: track the most recent commit timestamp each file was touched in
    let mut file_last_modified: HashMap<String, i64> = HashMap::new();
    let mut count = 0;

    for oid in revwalk {
        if count >= 1000 {
            break;
        }
        let Ok(oid) = oid else { break };
        let Ok(commit) = repo.find_commit(oid) else {
            break;
        };
        let Ok(tree) = commit.tree() else { break };
        let parent_tree = commit.parent(0).ok().and_then(|p| p.tree().ok());

        let mut diff_opts = DiffOptions::new();
        let Ok(diff) = repo.diff_tree_to_tree(
            parent_tree.as_ref(),
            Some(&tree),
            Some(&mut diff_opts),
        ) else {
            break;
        };

        let ts = commit.time().seconds();
        let _ = diff.foreach(
            &mut |delta, _| {
                if let Some(path) = delta.new_file().path() {
                    let p = path.to_string_lossy().to_string();
                    // Only record the first (most recent) time we see this file
                    file_last_modified.entry(p).or_insert(ts);
                }
                true
            },
            None,
            None,
            None,
        );

        count += 1;
    }

    // Sort by oldest modification date
    let mut sorted: Vec<_> = file_last_modified.into_iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    sorted.truncate(limit);

    let rows: Vec<Vec<String>> = sorted
        .iter()
        .filter_map(|(path, ts)| {
            let dt = DateTime::<Utc>::from_timestamp(*ts, 0)?.naive_utc();
            Some(vec![path.clone(), dt.format("%Y-%m-%d").to_string()])
        })
        .collect();
    display::print_table(&["File", "Last Modified"], &rows);

    Ok(())
}

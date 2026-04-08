use git2::{Repository, Signature, StatusOptions};
use std::path::Path;

pub fn open_repo() -> Result<Repository, git2::Error> {
    Repository::discover(".")
}

pub fn init(path: &str) -> Result<(), git2::Error> {
    let repo = Repository::init(path)?;
    println!(
        "Initialized empty git repository in {}",
        repo.path().display()
    );
    Ok(())
}

pub fn status() -> Result<(), git2::Error> {
    let repo = open_repo()?;
    let mut opts = StatusOptions::new();
    opts.include_untracked(true);

    let statuses = repo.statuses(Some(&mut opts))?;

    if statuses.is_empty() {
        println!("Nothing to commit, working tree clean");
        return Ok(());
    }

    for entry in statuses.iter() {
        let status = entry.status();
        let path = entry.path().unwrap_or("???");

        let marker = if status.is_index_new() {
            "new file:   "
        } else if status.is_index_modified() || status.is_wt_modified() {
            "modified:   "
        } else if status.is_index_deleted() || status.is_wt_deleted() {
            "deleted:    "
        } else if status.is_index_renamed() || status.is_wt_renamed() {
            "renamed:    "
        } else if status.is_wt_new() {
            "untracked:  "
        } else {
            "            "
        };

        println!("  {marker}{path}");
    }

    Ok(())
}

pub fn add(files: &[String]) -> Result<(), git2::Error> {
    let repo = open_repo()?;
    let mut index = repo.index()?;

    for file in files {
        if file == "." {
            index.add_all(["*"], git2::IndexAddOption::DEFAULT, None)?;
        } else {
            index.add_path(Path::new(file))?;
        }
    }

    index.write()?;
    println!("Files staged successfully");
    Ok(())
}

pub fn commit(message: &str) -> Result<(), git2::Error> {
    let repo = open_repo()?;
    let mut index = repo.index()?;
    let oid = index.write_tree()?;
    let tree = repo.find_tree(oid)?;

    let sig = repo
        .signature()
        .or_else(|_| Signature::now("codejourney", "codejourney@localhost"))?;

    let parent_commit = repo
        .head()
        .ok()
        .and_then(|head| head.peel_to_commit().ok());

    match parent_commit {
        Some(parent) => {
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[&parent])?;
        }
        None => {
            repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &[])?;
        }
    }

    println!("Committed: {message}");
    Ok(())
}

pub fn log(count: usize) -> Result<(), git2::Error> {
    let repo = open_repo()?;
    let mut revwalk = repo.revwalk()?;
    revwalk.push_head()?;
    revwalk.set_sorting(git2::Sort::TIME)?;

    for (i, oid) in revwalk.enumerate() {
        if i >= count {
            break;
        }
        let oid = oid?;
        let commit = repo.find_commit(oid)?;
        let message = commit.message().unwrap_or("<no message>");
        let author = commit.author();
        let name = author.name().unwrap_or("unknown");

        println!(
            "\x1b[33m{}\x1b[0m {} - {}",
            &oid.to_string()[..7],
            message.trim(),
            name
        );
    }

    Ok(())
}

pub fn branch(name: &str) -> Result<(), git2::Error> {
    let repo = open_repo()?;
    let head = repo.head()?.peel_to_commit()?;
    repo.branch(name, &head, false)?;
    println!("Created branch: {name}");
    Ok(())
}

pub fn checkout(name: &str) -> Result<(), git2::Error> {
    let repo = open_repo()?;

    let refname = format!("refs/heads/{name}");
    let obj = repo.revparse_single(&refname)?;

    repo.checkout_tree(&obj, None)?;
    repo.set_head(&refname)?;
    println!("Switched to branch: {name}");
    Ok(())
}

pub fn diff() -> Result<(), git2::Error> {
    let repo = open_repo()?;
    let diff = repo.diff_index_to_workdir(None, None)?;

    diff.print(git2::DiffFormat::Patch, |_delta, _hunk, line| {
        let prefix = match line.origin() {
            '+' => "\x1b[32m+",
            '-' => "\x1b[31m-",
            _ => " ",
        };
        print!(
            "{prefix}{}\x1b[0m",
            std::str::from_utf8(line.content()).unwrap_or("")
        );
        true
    })?;

    Ok(())
}

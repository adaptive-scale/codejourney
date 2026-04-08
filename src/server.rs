use axum::http::StatusCode;
use axum::{extract::Query, routing::get, Json, Router};
use git2::{Repository, StatusOptions};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

fn open_repo() -> Result<Repository, git2::Error> {
    Repository::discover(".")
}

#[derive(Serialize)]
struct StatusEntry {
    path: String,
    status: String,
}

#[derive(Serialize)]
struct LogEntry {
    hash: String,
    message: String,
    author: String,
}

#[derive(Deserialize)]
struct LogParams {
    count: Option<usize>,
}

#[derive(Serialize)]
struct ApiResponse<T: Serialize> {
    ok: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    ok: bool,
    error: String,
}

type ApiError = (StatusCode, Json<ErrorResponse>);

fn api_error(msg: String) -> ApiError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            ok: false,
            error: msg,
        }),
    )
}

async fn handle_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "status": "healthy" }))
}

async fn handle_status() -> Result<Json<ApiResponse<Vec<StatusEntry>>>, ApiError> {
    let repo = open_repo().map_err(|e| api_error(e.to_string()))?;
    let mut opts = StatusOptions::new();
    opts.include_untracked(true);

    let statuses = repo
        .statuses(Some(&mut opts))
        .map_err(|e| api_error(e.to_string()))?;

    let entries: Vec<StatusEntry> = statuses
        .iter()
        .map(|entry| {
            let status = entry.status();
            let label = if status.is_index_new() {
                "new"
            } else if status.is_index_modified() || status.is_wt_modified() {
                "modified"
            } else if status.is_index_deleted() || status.is_wt_deleted() {
                "deleted"
            } else if status.is_wt_new() {
                "untracked"
            } else {
                "other"
            };
            StatusEntry {
                path: entry.path().unwrap_or("???").to_string(),
                status: label.to_string(),
            }
        })
        .collect();

    Ok(Json(ApiResponse {
        ok: true,
        data: entries,
    }))
}

async fn handle_log(Query(params): Query<LogParams>) -> Result<Json<ApiResponse<Vec<LogEntry>>>, ApiError> {
    let count = params.count.unwrap_or(10);
    let repo = open_repo().map_err(|e| api_error(e.to_string()))?;
    let mut revwalk = repo.revwalk().map_err(|e| api_error(e.to_string()))?;
    revwalk.push_head().map_err(|e| api_error(e.to_string()))?;
    revwalk
        .set_sorting(git2::Sort::TIME)
        .map_err(|e| api_error(e.to_string()))?;

    let mut entries = Vec::new();
    for (i, oid) in revwalk.enumerate() {
        if i >= count {
            break;
        }
        let oid = oid.map_err(|e| api_error(e.to_string()))?;
        let commit = repo.find_commit(oid).map_err(|e| api_error(e.to_string()))?;
        entries.push(LogEntry {
            hash: oid.to_string()[..7].to_string(),
            message: commit.message().unwrap_or("").trim().to_string(),
            author: commit.author().name().unwrap_or("unknown").to_string(),
        });
    }

    Ok(Json(ApiResponse {
        ok: true,
        data: entries,
    }))
}

async fn handle_diff() -> Result<Json<ApiResponse<String>>, ApiError> {
    let repo = open_repo().map_err(|e| api_error(e.to_string()))?;
    let diff = repo
        .diff_index_to_workdir(None, None)
        .map_err(|e| api_error(e.to_string()))?;

    let mut output = String::new();
    diff.print(git2::DiffFormat::Patch, |_delta, _hunk, line| {
        let prefix = match line.origin() {
            '+' => "+",
            '-' => "-",
            _ => " ",
        };
        output.push_str(prefix);
        output.push_str(std::str::from_utf8(line.content()).unwrap_or(""));
        true
    })
    .map_err(|e| api_error(e.to_string()))?;

    Ok(Json(ApiResponse {
        ok: true,
        data: output,
    }))
}

pub async fn serve(port: u16) {
    let app = Router::new()
        .route("/health", get(handle_health))
        .route("/status", get(handle_status))
        .route("/log", get(handle_log))
        .route("/diff", get(handle_diff));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    println!("Server listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

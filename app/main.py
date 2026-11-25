from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .database import Base, engine, get_db
from . import models, schemas
from .services import CodeFetcher, AnalyzerCore, QualityGateService, ReportGenerator

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(title="SAST Analyzer API",
              description="Учебный прототип анализатора безопасности исходного кода (вариант 25)",
              version="1.0.0", lifespan=lifespan)

code_fetcher, analyzer = CodeFetcher(), AnalyzerCore()
quality_gate, report_generator = QualityGateService(), ReportGenerator()

def get_project_or_404(db: Session, project_id: int):
    project = db.get(models.Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Проект не найден")
    return project

def get_scan_or_404(db: Session, scan_id: int):
    scan = db.get(models.ScanTask, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")
    return scan

@app.get("/", tags=["system"])
def root():
    return {"service": "SAST Analyzer API", "docs": "/docs", "version": app.version}

@app.post("/projects", response_model=schemas.ProjectRead, status_code=201, tags=["projects"])
def create_project(payload: schemas.ProjectCreate, db: Session = Depends(get_db)):
    project = models.Project(**payload.model_dump())
    db.add(project); db.commit(); db.refresh(project)
    return project

@app.get("/projects", response_model=list[schemas.ProjectRead], tags=["projects"])
def list_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).order_by(models.Project.id).all()

@app.get("/projects/{project_id}", response_model=schemas.ProjectRead, tags=["projects"])
def get_project(project_id: int, db: Session = Depends(get_db)):
    return get_project_or_404(db, project_id)

@app.put("/projects/{project_id}", response_model=schemas.ProjectRead, tags=["projects"])
def update_project(project_id: int, payload: schemas.ProjectUpdate, db: Session = Depends(get_db)):
    project = get_project_or_404(db, project_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, key, value)
    db.commit(); db.refresh(project)
    return project

@app.delete("/projects/{project_id}", status_code=204, tags=["projects"])
def delete_project(project_id: int, db: Session = Depends(get_db)):
    project = get_project_or_404(db, project_id)
    db.delete(project); db.commit()
    return None

@app.post("/scans", response_model=schemas.ScanRead, status_code=201, tags=["scans"])
def create_scan(payload: schemas.ScanCreate, db: Session = Depends(get_db)):
    project = code_fetcher.fetch(db, payload.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Проект не найден")
    scan = models.ScanTask(project_id=project.id, status="running")
    db.add(scan); db.flush()
    for item in analyzer.analyze(project.source_code):
        db.add(models.Finding(scan_id=scan.id, **item))
    db.flush()
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan.id).all()
    threshold_config = db.query(models.ThresholdConfig).order_by(models.ThresholdConfig.id).first()
    if threshold_config is None:
        threshold_config = models.ThresholdConfig(max_critical=0, max_high=0)
        db.add(threshold_config)
        db.flush()
    db.add(models.GateDecision(scan_id=scan.id, **quality_gate.evaluate(findings, threshold_config)))
    scan.status = "completed"
    db.commit(); db.refresh(scan)
    return {"id": scan.id, "project_id": scan.project_id, "status": scan.status,
            "created_at": scan.created_at, "findings_count": len(findings)}

@app.get("/scans", response_model=list[schemas.ScanRead], tags=["scans"])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(models.ScanTask).order_by(models.ScanTask.id).all()
    return [{"id": s.id, "project_id": s.project_id, "status": s.status,
             "created_at": s.created_at, "findings_count": len(s.findings)} for s in scans]

@app.get("/scans/{scan_id}", response_model=schemas.ScanRead, tags=["scans"])
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan_or_404(db, scan_id)
    return {"id": scan.id, "project_id": scan.project_id, "status": scan.status,
            "created_at": scan.created_at, "findings_count": len(scan.findings)}

@app.get("/scans/{scan_id}/findings", response_model=list[schemas.FindingRead], tags=["findings"])
def list_findings(scan_id: int, db: Session = Depends(get_db)):
    get_scan_or_404(db, scan_id)
    return db.query(models.Finding).filter(models.Finding.scan_id == scan_id).order_by(models.Finding.id).all()

@app.get("/scans/{scan_id}/quality-gate", response_model=schemas.GateDecisionRead, tags=["quality-gate"])
def get_quality_gate(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan_or_404(db, scan_id)
    if scan.gate_decision is None:
        raise HTTPException(status_code=404, detail="Решение Quality Gate не найдено")
    return scan.gate_decision

@app.post("/scans/{scan_id}/reports", response_model=schemas.ReportRead, status_code=201, tags=["reports"])
def create_report(scan_id: int, payload: schemas.ReportCreate, db: Session = Depends(get_db)):
    scan = get_scan_or_404(db, scan_id)
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    report = models.ReportArtifact(scan_id=scan_id, format=payload.format,
                                   content=report_generator.generate(scan, findings, payload.format))
    db.add(report); db.commit(); db.refresh(report)
    return report

@app.get("/reports/{report_id}", response_model=schemas.ReportRead, tags=["reports"])
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(models.ReportArtifact, report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Отчёт не найден")
    return report

"""PHP reachability from the route table.

Measured before this existed: every PHP finding on a real Symfony project came
back with zero callers. Phpactor advertises no `callHierarchy`, and `references`
finds nothing for a controller action because nothing in the codebase calls it —
the framework does, from a table the language server never reads.
"""

from __future__ import annotations

from appsec_triage.config import PipelineConfig
from appsec_triage.context import builder
from appsec_triage.context.heuristics import HeuristicResult
from appsec_triage.context.routes import build_index
from appsec_triage.models import CodeContext, Finding

CONTROLLER = '''<?php

namespace App\\Controller;

use App\\Service\\ReportService;

class EventsController
{
    /**
     * @Route(name="push_event", path="push/event/created", methods="POST")
     */
    public function pushEvent(Request $request)
    {
        $service = new ReportService();
        return $service->build($request->get('id'));
    }

    public function helper()
    {
        return 1;
    }
}
'''

SERVICE = '''<?php

namespace App\\Service;

class ReportService
{
    public function build($id)
    {
        return $this->conn->query("SELECT * FROM reports WHERE id = $id");
    }
}
'''


def _tree(tmp_path):
    (tmp_path / "src" / "Controller").mkdir(parents=True)
    (tmp_path / "src" / "Service").mkdir(parents=True)
    (tmp_path / "src" / "Controller" / "EventsController.php").write_text(CONTROLLER, encoding="utf-8")
    (tmp_path / "src" / "Service" / "ReportService.php").write_text(SERVICE, encoding="utf-8")
    return build_index([tmp_path])


def test_a_docblock_annotation_registers_an_entry_point(tmp_path):
    # The multi-line `@Route` docblock form, which is what the project that
    # exposed this gap actually uses — not the modern attribute.
    index = _tree(tmp_path)
    assert len(index.routes) == 1
    route = index.routes[0]
    assert route.method == "pushEvent"
    assert route.path == "push/event/created"
    assert route.http_methods == "POST"


def test_the_route_name_is_not_mistaken_for_the_path(tmp_path):
    # `@Route(name="push_event", path=...)`: taking the first quoted literal
    # reports the name as the URL and sends the reviewer to the wrong endpoint.
    assert _tree(tmp_path).routes[0].path != "push_event"


def test_a_line_inside_the_routed_method_is_an_entry_point(tmp_path):
    index = _tree(tmp_path)
    assert index.enclosing("src/Controller/EventsController.php", 15) is not None
    # ...and a sibling method that carries no route is not.
    assert index.enclosing("src/Controller/EventsController.php", 20) is None


def test_a_service_two_hops_down_is_still_inside_the_perimeter(tmp_path):
    # This is the case that matters. The sink is never in the controller; it is
    # in a service the controller names, and answering only "is this a routed
    # method" would report nothing about the file that holds the injection.
    index = _tree(tmp_path)
    hit = index.perimeter("src/Service/ReportService.php")
    assert hit is not None
    hops, _chain = hit
    assert hops == 1


def test_an_unreferenced_file_gets_no_answer_rather_than_unreachable(tmp_path):
    # Silence must never read as "safe": console commands, subscribers and
    # message handlers are entry points this index does not model.
    index = _tree(tmp_path)
    (tmp_path / "src" / "Orphan.php").write_text("<?php class Orphan {}", encoding="utf-8")
    assert index.perimeter("src/Orphan.php") is None


def test_the_entry_point_becomes_a_signal_and_the_perimeter_does_not(tmp_path):
    """The distinction the whole design rests on.

    Being *in* a routed action is evidence about exploitability. Being two
    references away is orientation for the reviewer — real enough to report,
    not real enough to push the verdict.
    """
    index = _tree(tmp_path)
    heur = HeuristicResult(
        signals=[], hard_fp=False, hard_fp_reason=None, in_noisy_zone=False, noisy_zone_reason=None
    )

    def build(path, line):
        finding = Finding(
            finding_id="f",
            scanner="semgrep",
            cwe="CWE-89",
            code_context=CodeContext(file_path=path, start_line=line, snippet="x"),
        )
        return builder.build(finding, heur, PipelineConfig(), routes=index)

    routed = build("src/Controller/EventsController.php", 15)
    signal = next(s for s in routed.heuristic_signals if s.name == "http_entrypoint_method")
    assert signal.direction == "toward_confirmed"
    assert "entry point" in (routed.reachability or "")

    nearby = build("src/Service/ReportService.php", 9)
    near = next(s for s in nearby.heuristic_signals if s.name == "near_http_entrypoint")
    assert near.direction == "neutral"
    assert near.weight == 0.0
    assert "does not prove" in near.detail


def test_the_reference_regex_actually_matches(tmp_path):
    """A regression guard with an embarrassing history.

    The word-boundary escape in this pattern was once written to the file as a
    literal backspace character. The regex still compiled, still printed as if
    it were correct, and matched nothing — so the perimeter silently collapsed
    to the routed files themselves and every service reported "no answer".
    """
    from appsec_triage.context.routes import _REFERENCED

    assert _REFERENCED.findall("class ReportService extends BaseThing") == ["ReportService", "BaseThing"]


def test_a_long_trace_keeps_its_sink():
    """The sink decides the verdict; taking the first N steps threw it away.

    Measured on a real Go project: a 215-step CodeQL trace reached the model
    with the log call missing, and the model abstained *because* of the gap —
    an `unknown` manufactured by our own cropping.
    """
    from appsec_triage.context.builder import _trim_trace
    from appsec_triage.models import TraceStep

    trace = [TraceStep(file_path=f"f{i}.go", line=i, role="step") for i in range(100)]
    trace[0].role = "source"
    trace[-1].role = "sink"

    kept, omitted = _trim_trace(trace, 12)
    assert omitted == 88
    assert kept[0] is trace[0]
    assert kept[-1] is trace[-1]
    # The gap is marked, not silently closed: a sanitizer could be inside it.
    assert None in kept


def test_a_short_trace_is_left_whole():
    from appsec_triage.context.builder import _trim_trace
    from appsec_triage.models import TraceStep

    trace = [TraceStep(file_path="a.go", line=1)]
    assert _trim_trace(trace, 12) == (trace, 0)

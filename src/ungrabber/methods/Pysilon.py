from .. import utils
import base64
from pycmatch import Pattern
from .. import classes

PATTERN = (
    Pattern()
    .expect("LOAD_CONST").arg_type(str)
    .expect("STORE_NAME").arg("auto")
    .match_until(
        match_each = (
            Pattern()
            .any_of(
                Pattern()
                .expect("LOAD_CONST").type_capture("tokens", str),
                
                Pattern().any().done()
            )
        ),
        
        end = Pattern().expect("BUILD_LIST").done()
    )
)

def main(file: classes.Stub) -> dict:

    if file.isExe:
        source_prepared = file.struct.get("source_prepared", None)
    else:
        source_prepared = file.struct[file.name]

    if not source_prepared:
        raise Exception("Couldn't Find The Source Prepared For Pysilon")

    loaded = utils.loadPyc(source_prepared, file.version)[0]

    match = PATTERN.search(loaded)
    
    if not match:
        raise Exception("Couldn't Find The Bytecode For Pysilon Tokens")
    
    tokens = [base64.b64decode(token[::-1]).decode() for token in match.get_all("tokens")]

    return {"webhooks": [], "tokens": tokens}

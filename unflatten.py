import argparse
from sys import exit

from state_transitions import AnalyzerContext, FunctionAnalyzer, FunctionNotFlattened
from graphs import StateToNodeMapping
from bin_rewrite import BinaryRewriteContext


def check_valid_mappings(stm: StateToNodeMapping):
    state_to_entrance = {}
    for addr, state in stm.dispatcher_exits.items():
        assert len(state) == 1
        state = list(state)[0]
        state_to_entrance[state] = addr
    dispatcher_entrance_states = set()

    for state in stm.conditional_jmps.values():
        assert len(state) >= 2
        dispatcher_entrance_states.update(state)
    for state in stm.unflat_conditionals.values():
        assert len(state) == 1
        dispatcher_entrance_states.update(state)
    for state in stm.dispatcher_entrance.values():
        assert len(state) == 1
        dispatcher_entrance_states.update(state)

    dispatcher_exit_states = set()
    for i in stm.dispatcher_exits.values():
        dispatcher_exit_states.update(i)
    assert (
        dispatcher_entrance_states == dispatcher_exit_states
    )  # all entrances have a mapped exit and vise versa


def unflatten_function(
    unflattener, func
) -> tuple[StateToNodeMapping, FunctionAnalyzer]:
    print(f"Beginning analysis of {hex(func)}")
    analyzer = unflattener.analyse(func)
    state_to_node = analyzer.run()
    check_valid_mappings(state_to_node)
    print(f"Finished analysis of {hex(func)}")

    return state_to_node, analyzer


def unflatten_all(fpath):
    not_fixed = []
    successfully_unflattened = []
    analyzer_ctx = AnalyzerContext(fpath)
    ctx = BinaryRewriteContext(fpath, analyzer_ctx)
    num_funcs = len(analyzer_ctx.master_cfg.functions)
    num_flat_funcs = num_funcs
    for i, f in enumerate(analyzer_ctx.master_cfg.functions):
        try:
            stm, analyzer = unflatten_function(analyzer_ctx, f)
        except FunctionNotFlattened:
            print(f"{hex(f)} is not a flattened function")
            num_flat_funcs -= 1
            continue
        except Exception:
            not_fixed.append(f)
            print(f"Unsuccessful in unflattening {hex(f)}")
            continue

        func_rewriter = ctx.FunctionRewriter(stm, analyzer)
        func_rewriter.run()
        successfully_unflattened.append(f)
        print(f"\nAnalyzed {i+1} of {num_funcs} functions\n")
    if not_fixed:
        print(f"Unable to unflatten the following functions:")
        for i in not_fixed:
            print(hex(i))
    print(
        f"Binary had {num_flat_funcs} functions flattend of {num_funcs}.\nSuccessfully unflattened {num_flat_funcs - len(not_fixed)} of {num_flat_funcs} functions"
    )
    print(f"Successfully unflattened the following functions: ")
    for i in successfully_unflattened:
        print(hex(i))
    ctx.write_bin()


def run_cli():
    parser = argparse.ArgumentParser(
        description="Control-flow unflattening tool for Emotet"
    )

    parser.add_argument("--binary", "-b", required=True, help="Path to binary")

    parser.add_argument(
        "--function",
        "-f",
        help="Function address to unflatten (hex or decimal). "
        "If omitted, all functions are processed.",
    )

    parser.add_argument(
        "--output", "-o", help="Output binary path (default: <input>.unflattened)"
    )

    args = parser.parse_args()

    fpath = args.binary
    outpath = args.output

    if args.function is None:
        # Whole-binary mode
        unflatten_all(fpath)
        return

    # Single-function mode
    try:
        func_addr = int(args.function, 0)  # handles 0x... and decimal
    except ValueError:
        print("Invalid function address")
        exit(1)

    analyzer_ctx = AnalyzerContext(fpath)
    ctx = BinaryRewriteContext(fpath, analyzer_ctx)

    try:
        stm, analyzer = unflatten_function(analyzer_ctx, func_addr)
    except FunctionNotFlattened:
        print(f"Function {hex(func_addr)} is not flattened")
        exit(1)
    except Exception as e:
        print(type(e).__name__, e)
        print(f"Unsuccessful in unflattening {hex(func_addr)}")
        exit(1)

    func_rewriter = ctx.FunctionRewriter(stm, analyzer)
    func_rewriter.run()

    ctx.write_bin(outpath)

    print(f"Successfully unflattened function {hex(func_addr)}")


def main():
    run_cli()


main()

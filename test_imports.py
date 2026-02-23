#!/usr/bin/env python3
"""
验证所有关键 angr 和依赖包导入是否正常

用于升级到 Python 3.10 + angr 9.2.x 后的验证
"""
import sys

def test_imports():
    errors = []
    warnings = []

    print("=" * 60)
    print("Karonte 依赖导入测试")
    print("=" * 60)
    print()

    # 测试 1: 基础 angr
    print("[1/8] 测试 angr...")
    try:
        import angr
        print(f"  ✓ angr {angr.__version__}")
    except Exception as e:
        errors.append(f"✗ angr: {e}")
        print(f"  ✗ angr: {e}")

    # 测试 2: angr 相关组件
    print("[2/8] 测试 angr 组件 (claripy, archinfo, cle, pyvex)...")
    try:
        import claripy
        import archinfo
        import cle
        import pyvex
        print(f"  ✓ claripy {claripy.__version__}")
        print(f"  ✓ archinfo {archinfo.__version__}")
        print(f"  ✓ cle {cle.__version__}")
        print(f"  ✓ pyvex {pyvex.__version__}")
    except Exception as e:
        errors.append(f"✗ angr 组件: {e}")
        print(f"  ✗ angr 组件: {e}")

    # 测试 3: Knowledge plugins
    print("[3/8] 测试 Knowledge plugins...")
    try:
        from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
        from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED
        print("  ✓ Knowledge plugins (OP_AFTER, UNDEFINED)")
    except ImportError as e:
        warnings.append(f"⚠ Knowledge plugins (原路径): {e}")
        print(f"  ⚠ 原导入路径失败: {e}")
        # 尝试替代导入
        try:
            from angr.knowledge_plugins.key_definitions import OP_AFTER, UNDEFINED
            print("  ✓ Knowledge plugins (替代导入路径)")
            warnings.append("需要更新 tool/bdg/cpfs/__init__.py 的导入路径")
        except Exception as e2:
            errors.append(f"✗ Knowledge plugins (所有路径): {e2}")
            print(f"  ✗ 替代路径也失败: {e2}")

    # 测试 4: SimProcedures
    print("[4/8] 测试 SimProcedures...")
    try:
        from angr.procedures.stubs.ReturnUnconstrained import ReturnUnconstrained
        print("  ✓ ReturnUnconstrained")
    except ImportError as e:
        warnings.append(f"⚠ ReturnUnconstrained (原路径): {e}")
        print(f"  ⚠ 原导入路径失败: {e}")
        try:
            from angr.sim_procedures.stubs.ReturnUnconstrained import ReturnUnconstrained
            print("  ✓ ReturnUnconstrained (替代路径)")
            warnings.append("需要更新 ReturnUnconstrained 导入路径")
        except Exception as e2:
            errors.append(f"✗ ReturnUnconstrained: {e2}")
            print(f"  ✗ 替代路径也失败: {e2}")

    # 测试 5: angr.options
    print("[5/8] 测试 angr.options...")
    try:
        from angr.options import LAZY_SOLVES
        print("  ✓ angr.options.LAZY_SOLVES")
    except ImportError:
        warnings.append("⚠ angr.options.LAZY_SOLVES 不存在")
        try:
            from angr.sim_options import LAZY_SOLVES
            print("  ✓ angr.sim_options.LAZY_SOLVES")
            warnings.append("需要更新 LAZY_SOLVES 导入路径")
        except Exception as e:
            errors.append(f"✗ LAZY_SOLVES: {e}")
            print(f"  ✗ LAZY_SOLVES: {e}")

    # 测试 6: 科学计算库
    print("[6/8] 测试科学计算库 (numpy, scikit-learn, networkx)...")
    try:
        import numpy
        import sklearn
        import networkx
        print(f"  ✓ numpy {numpy.__version__}")
        print(f"  ✓ scikit-learn {sklearn.__version__}")
        print(f"  ✓ networkx {networkx.__version__}")

        # 检查 NumPy 版本
        numpy_major = int(numpy.__version__.split('.')[0])
        if numpy_major >= 2:
            warnings.append(f"⚠ NumPy 版本为 {numpy.__version__}，可能不兼容！应使用 <2.0.0")
            print(f"  ⚠ 警告: NumPy 版本 {numpy.__version__} >= 2.0，可能不兼容")
    except Exception as e:
        errors.append(f"✗ 科学计算库: {e}")
        print(f"  ✗ {e}")

    # 测试 7: 其他依赖
    print("[7/8] 测试其他依赖 (mpmath, sympy, python-magic)...")
    try:
        import mpmath
        import sympy
        import magic
        print(f"  ✓ mpmath {mpmath.__version__}")
        print(f"  ✓ sympy {sympy.__version__}")
        print("  ✓ python-magic")
    except Exception as e:
        errors.append(f"✗ 其他依赖: {e}")
        print(f"  ✗ {e}")

    # 测试 8: progressbar2
    print("[8/8] 测试 progressbar2...")
    try:
        import progressbar2
        print(f"  ✓ progressbar2 (版本: {progressbar2.__version__ if hasattr(progressbar2, '__version__') else 'unknown'})")
    except Exception as e:
        errors.append(f"✗ progressbar2: {e}")
        print(f"  ✗ progressbar2: {e}")

    # 总结
    print()
    print("=" * 60)
    if not errors and not warnings:
        print("✅ 所有测试通过！")
        print("=" * 60)
        return True
    else:
        if warnings:
            print("⚠️  发现警告:")
            for warn in warnings:
                print(f"  {warn}")
            print()

        if errors:
            print("❌ 发现错误:")
            for err in errors:
                print(f"  {err}")
            print()
            print("请根据错误信息修复代码后重试")
        else:
            print("✅ 所有导入成功（有警告需要关注）")

        print("=" * 60)
        return len(errors) == 0

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)

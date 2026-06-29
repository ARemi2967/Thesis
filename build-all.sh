#!/bin/bash

# 批量编译所有链容器的JAR包
# 支持从 generated-env 目录动态检测所有生成的环境

echo "==========================================="
echo "开始编译所有链容器..."
echo "==========================================="

cd "$(dirname "$0")"

# 编译Gateway
echo ""
echo "==========================================="
echo "编译 Gateway"
echo "==========================================="
cd gateway
if mvn clean package -DskipTests; then
    echo "[OK] Gateway 编译成功"
else
    echo "[ERROR] Gateway 编译失败"
    exit 1
fi
cd ..

# 从generated-env目录动态获取所有链
echo ""
echo "==========================================="
echo "检测生成的链环境..."
echo "==========================================="

if [ ! -d "generated-env" ]; then
    echo "[ERROR] generated-env 目录不存在"
    echo "请先运行 MCP 工具生成环境: python mcp-tools/mcp_server.py --cli --generate-all"
    exit 1
fi

# 获取所有包含pom.xml的目录
chains=()
while IFS= read -r -d '' dir; do
    chain_name=$(basename "$dir")
    chains+=("$chain_name")
done < <(find generated-env -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

if [ ${#chains[@]} -eq 0 ]; then
    echo "[WARNING] 未在 generated-env 中找到任何链环境"
    echo "请先生成环境: python mcp-tools/mcp_server.py --cli --generate-all"
    exit 0
fi

echo "发现 ${#chains[@]} 个链环境:"
for chain in "${chains[@]}"; do
    echo "  - $chain"
done

# 统计变量
success_count=0
failed_count=0
skipped_count=0

# 编译每个链容器
for chain in "${chains[@]}"; do
    echo ""
    echo "==========================================="
    echo "编译: $chain"
    echo "==========================================="

    chain_dir="generated-env/$chain"

    # 检查目录是否存在
    if [ ! -d "$chain_dir" ]; then
        echo "[SKIP] 目录不存在: $chain_dir"
        ((skipped_count++))
        continue
    fi

    # 检查pom.xml是否存在
    if [ ! -f "$chain_dir/pom.xml" ]; then
        echo "[SKIP] 未找到 pom.xml: $chain_dir/pom.xml"
        ((skipped_count++))
        continue
    fi

    cd "$chain_dir"

    if mvn clean package -DskipTests -q; then
        echo "[OK] $chain 编译成功"
        ((success_count++))
    else
        echo "[ERROR] $chain 编译失败"
        ((failed_count++))
        # 继续编译其他链，不退出
    fi

    cd - > /dev/null

done

echo ""
echo "==========================================="
echo "编译完成统计"
echo "==========================================="
echo "成功: $success_count"
echo "失败: $failed_count"
echo "跳过: $skipped_count"
echo "总计: ${#chains[@]}"
echo "==========================================="

if [ $failed_count -gt 0 ]; then
    echo "[WARNING] 有 $failed_count 个链编译失败"
    exit 1
fi

echo "[OK] 所有组件编译完成！"

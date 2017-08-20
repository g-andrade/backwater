defmodule ModuleWithBackwaterExports do
  def backwater_export do
    [{:function1,0}]
  end

  def function1 do
    :foobar
  end

  def function2 do
    :barfoo
  end
end

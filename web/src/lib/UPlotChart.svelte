<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';

  type Props = {
    data?: uPlot.AlignedData;
    options: uPlot.Options;
  };

  let { data, options }: Props = $props();

  let el: HTMLDivElement;
  let chart: uPlot | null = null;

  onMount(() => {
    chart = new uPlot(options, data ?? [[]], el);
  });

  $effect(() => {
    if (chart && data) {
      chart.setData(data);
    }
  });

  onDestroy(() => {
    chart?.destroy();
    chart = null;
  });
</script>

<div bind:this={el} class="uplot-chart w-full"></div>

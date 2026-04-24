"use client";

import { useEffect, useRef } from "react";
import * as THREE from "three";

/**
 * Tactical Night hero — a slowly rotating wireframe globe with pulsing arcs
 * with decorative surface markers. Pure three.js (no extras), so the bundle
 * stays tight.
 */
export default function Globe({ height = 360 }: { height?: number }) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    const w = el.clientWidth;
    const h = height;
    renderer.setSize(w, h);
    el.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
    camera.position.set(0, 0, 4.6);

    // Wire globe
    const globeGeo = new THREE.SphereGeometry(1.6, 48, 32);
    const wire = new THREE.LineSegments(
      new THREE.WireframeGeometry(globeGeo),
      new THREE.LineBasicMaterial({ color: 0x22e4c4, transparent: true, opacity: 0.35 })
    );
    scene.add(wire);

    // Inner solid (subtle tint)
    const inner = new THREE.Mesh(
      new THREE.SphereGeometry(1.58, 48, 32),
      new THREE.MeshBasicMaterial({ color: 0x0b0f14, transparent: true, opacity: 0.7 })
    );
    scene.add(inner);

    // Decorative markers (deterministic per index, not live SIEM data)
    const N = 36;
    const dotGeo = new THREE.SphereGeometry(0.025, 8, 8);
    const dots: THREE.Mesh[] = [];
    const unitRand = (i: number) => {
      const s = Math.sin(i * 12.9898 + 78.233) * 43758.5453;
      return s - Math.floor(s);
    };
    for (let i = 0; i < N; i++) {
      const m = new THREE.Mesh(
        dotGeo,
        new THREE.MeshBasicMaterial({ color: i % 5 === 0 ? 0xff5562 : 0xffb547 })
      );
      const u = unitRand(i);
      const v = unitRand(i + 17);
      const theta = 2 * Math.PI * u;
      const phi = Math.acos(2 * v - 1);
      const r = 1.62;
      m.position.set(
        r * Math.sin(phi) * Math.cos(theta),
        r * Math.sin(phi) * Math.sin(theta),
        r * Math.cos(phi)
      );
      scene.add(m);
      dots.push(m);
    }

    let raf = 0;
    let t = 0;
    const animate = () => {
      t += 0.005;
      wire.rotation.y = t;
      inner.rotation.y = t;
      dots.forEach((d, i) => {
        const s = 1 + 0.4 * Math.sin(t * 2 + i);
        d.scale.setScalar(s);
      });
      renderer.render(scene, camera);
      raf = requestAnimationFrame(animate);
    };
    animate();

    const onResize = () => {
      const newW = el.clientWidth;
      renderer.setSize(newW, h);
      camera.aspect = newW / h;
      camera.updateProjectionMatrix();
    };
    window.addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", onResize);
      renderer.dispose();
      el.removeChild(renderer.domElement);
    };
  }, [height]);

  return <div ref={ref} style={{ width: "100%", height }} />;
}

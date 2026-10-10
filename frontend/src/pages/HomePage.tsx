import Hero from '../components/Hero';
import PageTransition from '../components/PageTransition';

export default function HomePage() {
  return (
    <PageTransition>
      <Hero />
    </PageTransition>
  );
}

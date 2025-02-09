const {
  pageSize,
  pointerSize
} = Process;

class CodeAllocator {
  constructor (sliceSize) {
    this.sliceSize = sliceSize;
    this.slicesPerPage = pageSize / sliceSize;

    this.pages = [];
    this.free = [];
  }

  allocateSlice (spec, alignment) {
    const anyLocation = spec.near === undefined;
    const anyAlignment = alignment === 1;
    if (anyLocation && anyAlignment) {
      const slice = this.free.pop();
      if (slice !== undefined) {
        return slice;
      }
    } else if (alignment < pageSize) {
      const { free } = this;
      const n = free.length;
      const alignMask = anyAlignment ? null : ptr(alignment - 1);
      for (let i = 0; i !== n; i++) {
        const slice = free[i];

        const satisfiesLocation = anyLocation || this._isSliceNear(slice, spec);
        const satisfiesAlignment = anyAlignment || slice.and(alignMask).isNull();

        if (satisfiesLocation && satisfiesAlignment) {
          return free.splice(i, 1)[0];
        }
      }
    }

    return this._allocatePage(spec);
  }

  _allocatePage (spec) {
    const page = Memory.alloc(pageSize, spec);

    const { sliceSize, slicesPerPage } = this;

    for (let i = 1; i !== slicesPerPage; i++) {
      const slice = page.add(i * sliceSize);
      this.free.push(slice);
    }

    this.pages.push(page);

    return page;
  }

  _isSliceNear (slice, spec) {
    const sliceEnd = slice.add(this.sliceSize);

    const { near, maxDistance } = spec;

    const startDistance = abs(near.sub(slice));
    const endDistance = abs(near.sub(sliceEnd));

    return startDistance.compare(maxDistance) <= 0 &&
        endDistance.compare(maxDistance) <= 0;
  }

  freeSlice (slice) {
    this.free.push(slice);
  }
}

function abs (nptr) {
  const shmt = (pointerSize === 4) ? 31 : 63;
  const mask = ptr(1).shl(shmt).not();
  return nptr.and(mask);
}

export default function makeAllocator (sliceSize) {
  return new CodeAllocator(sliceSize);
}
